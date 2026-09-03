/*
 * SPDX-License-Identifier: MIT
 *
 * Self-contained cross-half soft-off signalling.
 *
 * A dedicated GATT service carries a one-byte "power off now" command between
 * the split halves so that triggering soft-off-plus on either half powers off
 * both. The central writes the command to each peripheral; a peripheral
 * notifies the central. The receiving side defers the actual power-off to a work
 * item so it never runs inside a Bluetooth callback.
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <zmk/soft_off_plus/off_marker.h>
#include <zmk/soft_off_plus/split_sync.h>

LOG_MODULE_DECLARE(zmk_soft_off_plus, CONFIG_ZMK_SOFT_OFF_PLUS_LOG_LEVEL);

#if !IS_ENABLED(CONFIG_ZMK_SOFT_OFF_PLUS_SPLIT_SYNC)

int zmk_soft_off_plus_signal_peers(void) { return 0; }
int zmk_soft_off_plus_signal_peers_drop(void) { return 0; }

#else /* CONFIG_ZMK_SOFT_OFF_PLUS_SPLIT_SYNC */

#include <errno.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/sys/atomic.h>

#include <zmk/soft_off_plus/uuid.h>

/* Defer the power-off so it never runs in a BLE RX callback context. */
static void sop_soft_off_work_cb(struct k_work *work) {
    ARG_UNUSED(work);
    if (!zmk_soft_off_plus_claim_off()) {
        return; /* this half is already powering off (e.g. its own keymap run) */
    }
    LOG_INF("soft-off-plus: peer requested simultaneous off");
    int err = zmk_soft_off_plus_pm_soft_off();
    LOG_ERR("soft-off-plus: peer System OFF returned unexpectedly (%d)", err);
    zmk_soft_off_plus_recover_from_failed_off();
    zmk_soft_off_plus_release_off_claim();
}
static K_WORK_DEFINE(sop_soft_off_work, sop_soft_off_work_cb);

/* DROP requested by a peer (trigger-on-hold phase 1 on the other half).
 *
 * If this half is holding its own soft-off-plus key (matrix relay, or the
 * sideband half the key is wired to), only request display blanking -- it powers
 * off on its own release, because the held key is also its wake source. If nothing is held
 * here (a passive receiver, e.g. the non-wired half of a sideband press), the
 * user has already committed to power-off by holding past hold-time and there is
 * no held wake source to re-wake us, so just power off now -- no need to wait for
 * a separate release signal to be relayed across the link. */
static void sop_drop_work_cb(struct k_work *work) {
    ARG_UNUSED(work);
    if (zmk_soft_off_plus_hold_active()) {
        LOG_INF("soft-off-plus: peer DROP; own key held, waiting for release");
        zmk_soft_off_plus_drop_components();
        return;
    }
    if (zmk_soft_off_plus_claim_off()) {
        LOG_INF("soft-off-plus: peer DROP; nothing held here, powering off");
        int err = zmk_soft_off_plus_pm_soft_off();
        LOG_ERR("soft-off-plus: peer DROP System OFF returned unexpectedly (%d)", err);
        zmk_soft_off_plus_recover_from_failed_off();
        zmk_soft_off_plus_release_off_claim();
    }
}
static K_WORK_DEFINE(sop_drop_work, sop_drop_work_cb);

/* Dispatch a received command byte. Runs from a BLE RX callback, so it only
 * submits work -- the actual suspend/power-off happens off the callback. */
static inline void sop_handle_cmd(uint8_t cmd) {
    switch (cmd) {
    case ZMK_SOFT_OFF_PLUS_CMD_OFF:
        k_work_submit(&sop_soft_off_work);
        break;
    case ZMK_SOFT_OFF_PLUS_CMD_DROP:
        k_work_submit(&sop_drop_work);
        break;
    default:
        break;
    }
}

#if IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL)

/* ---------------------------------------------------------------------------
 * Central: GATT client. Discovers the off characteristic on each peripheral,
 * subscribes for notifications, and writes the off command on demand.
 *
 * Discovery is driven from a retrying work item rather than directly from the
 * connected callback: ZMK's own split client kicks off a GATT discovery the
 * instant the link comes up, and only one GATT procedure can be active per
 * connection, so a discovery started from our connected callback races ZMK's
 * and fails with -EBUSY. The work item waits until the link is encrypted and
 * the ATT bearer is free, then retries until it has our handle.
 * ------------------------------------------------------------------------- */

#include <zmk/ble.h>

enum sop_slot_phase {
    SOP_SLOT_EMPTY,
    SOP_SLOT_WAIT_SECURITY,
    SOP_SLOT_DISCOVERY_READY,
    SOP_SLOT_DISCOVERING_SERVICE,
    SOP_SLOT_DISCOVERING_CHARACTERISTIC,
    SOP_SLOT_SUBSCRIPTION_READY,
    SOP_SLOT_SUBSCRIBING,
    SOP_SLOT_SUBSCRIBED,
};

struct sop_peripheral_slot {
    /* The slot owns this reference until the matching disconnect callback. */
    struct bt_conn *conn;
    uint32_t generation;
    enum sop_slot_phase phase;
    uint16_t off_handle;
    uint32_t retry_ms;
    struct bt_gatt_discover_params discover_params;
    struct bt_gatt_discover_params sub_discover_params;
    struct bt_gatt_subscribe_params subscribe_params;
};

static struct sop_peripheral_slot peripherals[ZMK_SPLIT_BLE_PERIPHERAL_COUNT];
static struct k_spinlock sop_slots_lock;

static const struct bt_uuid_128 sop_service_uuid = BT_UUID_INIT_128(ZMK_SOFT_OFF_PLUS_SVC_UUID);

static void sop_discover_work_cb(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(sop_discover_work, sop_discover_work_cb);

/* Long enough for ZMK's own connect-time discovery to finish and free the ATT
 * bearer before we (re)try ours. */
#define SOP_DISCOVER_RETRY_MS 500U
#define SOP_DISCOVER_RETRY_MAX_MS 5000U

struct sop_slot_snapshot {
    struct bt_conn *conn;
    uint32_t generation;
    enum sop_slot_phase phase;
    uint16_t off_handle;
};

/* The caller must hold sop_slots_lock. */
static struct sop_peripheral_slot *sop_slot_for_conn_locked(struct bt_conn *conn) {
    if (!conn) {
        return NULL;
    }

    for (int i = 0; i < ZMK_SPLIT_BLE_PERIPHERAL_COUNT; i++) {
        if (peripherals[i].conn == conn) {
            return &peripherals[i];
        }
    }
    return NULL;
}

static bool sop_slot_matches_locked(struct sop_peripheral_slot *slot, struct bt_conn *conn,
                                    uint32_t generation) {
    return slot->conn == conn && slot->generation == generation;
}

static void sop_reset_retry_locked(struct sop_peripheral_slot *slot) {
    slot->retry_ms = SOP_DISCOVER_RETRY_MS;
}

static uint32_t sop_next_retry_locked(struct sop_peripheral_slot *slot) {
    uint32_t delay = slot->retry_ms ? slot->retry_ms : SOP_DISCOVER_RETRY_MS;

    slot->retry_ms = MIN(delay * 2U, SOP_DISCOVER_RETRY_MAX_MS);
    return delay;
}

static void sop_schedule_discovery(uint32_t delay_ms) {
    k_work_reschedule(&sop_discover_work, K_MSEC(delay_ms));
}

/* Take a short-lived connection reference while still holding the slot lock.
 * This closes the check/use window with the disconnect callback; callers may
 * then use the snapshot without keeping the lock across Bluetooth APIs. */
static bool sop_snapshot_slot(int index, struct sop_slot_snapshot *snapshot) {
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = &peripherals[index];

    if (slot->conn == NULL) {
        k_spin_unlock(&sop_slots_lock, key);
        return false;
    }

    snapshot->conn = bt_conn_ref(slot->conn);
    if (snapshot->conn == NULL) {
        k_spin_unlock(&sop_slots_lock, key);
        return false;
    }
    snapshot->generation = slot->generation;
    snapshot->phase = slot->phase;
    snapshot->off_handle = slot->off_handle;
    k_spin_unlock(&sop_slots_lock, key);
    return true;
}

static uint8_t sop_notify_cb(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
                             const void *data, uint16_t length) {
    uint32_t retry_delay = 0U;
    bool accept_command = false;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);

    if (slot == NULL || params != &slot->subscribe_params) {
        k_spin_unlock(&sop_slots_lock, key);
        return BT_GATT_ITER_STOP;
    }

    if (!data) {
        /* A NULL notification means that the subscription was removed or its
         * CCC could not be discovered. Keep the value handle for the
         * central->peripheral write path, but rediscover the CCC and retry the
         * peripheral->central notification path. */
        slot->phase = slot->off_handle ? SOP_SLOT_SUBSCRIPTION_READY : SOP_SLOT_DISCOVERY_READY;
        params->ccc_handle = BT_GATT_AUTO_DISCOVER_CCC_HANDLE;
        params->value_handle = slot->off_handle;
        params->value = BT_GATT_CCC_NOTIFY;
        retry_delay = sop_next_retry_locked(slot);
        k_spin_unlock(&sop_slots_lock, key);
        sop_schedule_discovery(retry_delay);
        return BT_GATT_ITER_STOP;
    }

    accept_command = slot->phase == SOP_SLOT_SUBSCRIBING || slot->phase == SOP_SLOT_SUBSCRIBED;
    k_spin_unlock(&sop_slots_lock, key);

    if (accept_command && length >= 1) {
        sop_handle_cmd(((const uint8_t *)data)[0]);
    }
    return BT_GATT_ITER_CONTINUE;
}

static void sop_subscribe_cb(struct bt_conn *conn, uint8_t err,
                             struct bt_gatt_subscribe_params *params) {
    uint32_t retry_delay = 0U;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);

    if (slot == NULL || params != &slot->subscribe_params ||
        slot->phase != SOP_SLOT_SUBSCRIBING) {
        k_spin_unlock(&sop_slots_lock, key);
        return;
    }

    if (err) {
        slot->phase = SOP_SLOT_SUBSCRIPTION_READY;
        retry_delay = sop_next_retry_locked(slot);
    } else {
        slot->phase = SOP_SLOT_SUBSCRIBED;
        sop_reset_retry_locked(slot);
    }
    k_spin_unlock(&sop_slots_lock, key);

    if (err) {
        LOG_WRN("soft-off-plus: subscribe response failed (ATT 0x%02x); retrying", err);
        sop_schedule_discovery(retry_delay);
    } else {
        LOG_DBG("soft-off-plus: peripheral notification subscription ready");
    }
}

static uint32_t sop_begin_subscription(int index, const struct sop_slot_snapshot *snapshot) {
    struct bt_gatt_subscribe_params *params;
    uint32_t retry_delay = 0U;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = &peripherals[index];

    if (!sop_slot_matches_locked(slot, snapshot->conn, snapshot->generation) ||
        slot->phase != SOP_SLOT_SUBSCRIPTION_READY) {
        k_spin_unlock(&sop_slots_lock, key);
        return 0U;
    }

    /* Always start a fresh automatic CCC discovery. If bt_gatt_discover()
     * fails synchronously (usually -EBUSY), Zephyr leaves disc_params->func
     * set to its internal discovery callback; without clearing it, every
     * subsequent bt_gatt_subscribe() returns -EBUSY forever. */
    memset(&slot->sub_discover_params, 0, sizeof(slot->sub_discover_params));
    slot->subscribe_params.disc_params = &slot->sub_discover_params;
    slot->subscribe_params.end_handle = slot->discover_params.end_handle;
    slot->subscribe_params.value_handle = slot->off_handle;
    slot->subscribe_params.ccc_handle = BT_GATT_AUTO_DISCOVER_CCC_HANDLE;
    slot->subscribe_params.notify = sop_notify_cb;
    slot->subscribe_params.subscribe = sop_subscribe_cb;
    slot->subscribe_params.value = BT_GATT_CCC_NOTIFY;

    /* Re-establish the CCC on every split reconnection. This prevents stale
     * client subscription state from making a peripheral notification appear
     * ready when the server no longer has notifications enabled. */
    atomic_set_bit(slot->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
    atomic_clear_bit(slot->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_NO_RESUB);

    slot->phase = SOP_SLOT_SUBSCRIBING;
    params = &slot->subscribe_params;
    k_spin_unlock(&sop_slots_lock, key);

    /* bt_gatt_subscribe() may invoke params->notify synchronously, so no slot
     * lock may be held across this call. The snapshot owns a temporary conn
     * reference for the entire operation. */
    int err = bt_gatt_subscribe(snapshot->conn, params);
    if (err == -EALREADY) {
        key = k_spin_lock(&sop_slots_lock);
        if (sop_slot_matches_locked(slot, snapshot->conn, snapshot->generation) &&
            slot->phase == SOP_SLOT_SUBSCRIBING) {
            /* The same live subscription is already registered. */
            slot->phase = SOP_SLOT_SUBSCRIBED;
            sop_reset_retry_locked(slot);
        }
        k_spin_unlock(&sop_slots_lock, key);
    } else if (err) {
        key = k_spin_lock(&sop_slots_lock);
        if (sop_slot_matches_locked(slot, snapshot->conn, snapshot->generation) &&
            slot->phase == SOP_SLOT_SUBSCRIBING) {
            slot->phase = SOP_SLOT_SUBSCRIPTION_READY;
            /* Clear Zephyr's auto-discovery in-progress marker after a
             * synchronous failure so the delayed work can make a genuinely
             * fresh attempt. */
            memset(&slot->sub_discover_params, 0, sizeof(slot->sub_discover_params));
            slot->subscribe_params.ccc_handle = BT_GATT_AUTO_DISCOVER_CCC_HANDLE;
            retry_delay = sop_next_retry_locked(slot);
        }
        k_spin_unlock(&sop_slots_lock, key);
        LOG_WRN("soft-off-plus: subscribe failed (%d); retrying", err);
    }

    return retry_delay;
}

static uint8_t sop_chrc_discovery_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                     struct bt_gatt_discover_params *params) {
    uint32_t retry_delay = 0U;
    uint16_t off_handle = 0U;
    bool found = false;
    bool exhausted = attr == NULL || attr->user_data == NULL;

    if (!exhausted) {
        const struct bt_uuid *chrc_uuid = ((struct bt_gatt_chrc *)attr->user_data)->uuid;
        found = bt_uuid_cmp(chrc_uuid, BT_UUID_DECLARE_128(ZMK_SOFT_OFF_PLUS_CHRC_UUID)) == 0;
        if (found) {
            off_handle = bt_gatt_attr_value_handle(attr);
        }
    }

    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);
    if (slot == NULL || params != &slot->discover_params ||
        slot->phase != SOP_SLOT_DISCOVERING_CHARACTERISTIC) {
        k_spin_unlock(&sop_slots_lock, key);
        return BT_GATT_ITER_STOP;
    }

    if (exhausted) {
        /* Walked the whole service without finding our characteristic; let the
         * work item decide whether to retry. */
        slot->phase = SOP_SLOT_DISCOVERY_READY;
        retry_delay = sop_next_retry_locked(slot);
        k_spin_unlock(&sop_slots_lock, key);
        sop_schedule_discovery(retry_delay);
        return BT_GATT_ITER_STOP;
    }

    if (!found) {
        /* Not ours; keep walking the rest of the service's characteristics. */
        k_spin_unlock(&sop_slots_lock, key);
        return BT_GATT_ITER_CONTINUE;
    }

    slot->off_handle = off_handle;
    slot->phase = SOP_SLOT_SUBSCRIPTION_READY;
    sop_reset_retry_locked(slot);
    k_spin_unlock(&sop_slots_lock, key);

    LOG_DBG("soft-off-plus: discovered peripheral off characteristic (handle %u)",
            off_handle);
    /* Do not start automatic CCC discovery from inside this characteristic
     * discovery callback: the ATT discovery procedure is still active until
     * this callback returns, so the nested bt_gatt_discover() gets -EBUSY and
     * poisons Zephyr's auto-discovery state. The retrying work item will start
     * the subscription after this procedure has completed. */
    sop_schedule_discovery(1U);
    return BT_GATT_ITER_STOP;
}

static uint8_t sop_service_discovery_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                        struct bt_gatt_discover_params *params) {
    uint32_t generation;
    uint32_t retry_delay = 0U;
    bool exhausted = attr == NULL || attr->user_data == NULL;
    uint16_t start_handle = 0U;
    uint16_t end_handle = 0U;

    if (!exhausted) {
        const struct bt_gatt_service_val *svc = attr->user_data;
        start_handle = attr->handle + 1U;
        end_handle = svc->end_handle;
    }

    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);
    if (slot == NULL || params != &slot->discover_params ||
        slot->phase != SOP_SLOT_DISCOVERING_SERVICE) {
        k_spin_unlock(&sop_slots_lock, key);
        return BT_GATT_ITER_STOP;
    }

    if (exhausted) {
        slot->phase = SOP_SLOT_DISCOVERY_READY;
        retry_delay = sop_next_retry_locked(slot);
        k_spin_unlock(&sop_slots_lock, key);
        sop_schedule_discovery(retry_delay);
        return BT_GATT_ITER_STOP;
    }

    /* Constrain the characteristic walk to this service's handle range. A bare
     * 0x0001..0xffff walk would hit the GAP/GATT characteristics first and stop
     * there, so our characteristic would never be found. */
    slot->discover_params.uuid = NULL;
    slot->discover_params.func = sop_chrc_discovery_cb;
    slot->discover_params.start_handle = start_handle;
    slot->discover_params.end_handle = end_handle;
    slot->discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
    slot->phase = SOP_SLOT_DISCOVERING_CHARACTERISTIC;
    generation = slot->generation;
    k_spin_unlock(&sop_slots_lock, key);

    /* The discovery callback can be invoked synchronously. */
    int err = bt_gatt_discover(conn, params);
    if (err) {
        key = k_spin_lock(&sop_slots_lock);
        slot = sop_slot_for_conn_locked(conn);
        if (slot != NULL && slot->generation == generation &&
            slot->phase == SOP_SLOT_DISCOVERING_CHARACTERISTIC) {
            slot->phase = SOP_SLOT_DISCOVERY_READY;
            retry_delay = sop_next_retry_locked(slot);
        }
        k_spin_unlock(&sop_slots_lock, key);
        LOG_WRN("soft-off-plus: characteristic discovery failed (%d)", err);
        if (retry_delay != 0U) {
            sop_schedule_discovery(retry_delay);
        }
    }
    return BT_GATT_ITER_STOP;
}

static uint32_t sop_begin_discovery(int index, const struct sop_slot_snapshot *snapshot) {
    struct bt_gatt_discover_params *params;
    uint32_t retry_delay = 0U;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = &peripherals[index];

    if (!sop_slot_matches_locked(slot, snapshot->conn, snapshot->generation) ||
        slot->phase != SOP_SLOT_DISCOVERY_READY) {
        k_spin_unlock(&sop_slots_lock, key);
        return 0U;
    }

    slot->discover_params.uuid = &sop_service_uuid.uuid;
    slot->discover_params.func = sop_service_discovery_cb;
    slot->discover_params.start_handle = 0x0001;
    slot->discover_params.end_handle = 0xffff;
    slot->discover_params.type = BT_GATT_DISCOVER_PRIMARY;
    slot->phase = SOP_SLOT_DISCOVERING_SERVICE;
    params = &slot->discover_params;
    k_spin_unlock(&sop_slots_lock, key);

    /* Discovery callbacks may run synchronously, so the slot lock is released
     * before entering the Bluetooth stack. */
    int err = bt_gatt_discover(snapshot->conn, params);
    if (err) {
        key = k_spin_lock(&sop_slots_lock);
        if (sop_slot_matches_locked(slot, snapshot->conn, snapshot->generation) &&
            slot->phase == SOP_SLOT_DISCOVERING_SERVICE) {
            slot->phase = SOP_SLOT_DISCOVERY_READY;
            retry_delay = sop_next_retry_locked(slot);
        }
        k_spin_unlock(&sop_slots_lock, key);
        /* Most likely -EBUSY while ZMK's own discovery runs; the work item
         * backs off and tries again. */
        LOG_DBG("soft-off-plus: service discovery busy (%d), will retry", err);
    }

    return retry_delay;
}

static void sop_discover_work_cb(struct k_work *work) {
    ARG_UNUSED(work);
    uint32_t next_retry = 0U;

    for (int i = 0; i < ZMK_SPLIT_BLE_PERIPHERAL_COUNT; i++) {
        struct sop_slot_snapshot snapshot;
        uint32_t retry_delay = 0U;

        if (!sop_snapshot_slot(i, &snapshot)) {
            continue;
        }

        if (snapshot.phase == SOP_SLOT_WAIT_SECURITY) {
            if (bt_conn_get_security(snapshot.conn) >= BT_SECURITY_L2) {
                k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
                struct sop_peripheral_slot *slot = &peripherals[i];

                if (sop_slot_matches_locked(slot, snapshot.conn, snapshot.generation) &&
                    slot->phase == SOP_SLOT_WAIT_SECURITY) {
                    slot->phase = SOP_SLOT_DISCOVERY_READY;
                    sop_reset_retry_locked(slot);
                    snapshot.phase = SOP_SLOT_DISCOVERY_READY;
                }
                k_spin_unlock(&sop_slots_lock, key);
            } else {
                k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
                struct sop_peripheral_slot *slot = &peripherals[i];

                if (sop_slot_matches_locked(slot, snapshot.conn, snapshot.generation) &&
                    slot->phase == SOP_SLOT_WAIT_SECURITY) {
                    retry_delay = sop_next_retry_locked(slot);
                }
                k_spin_unlock(&sop_slots_lock, key);
            }
        }

        if (snapshot.phase == SOP_SLOT_DISCOVERY_READY) {
            retry_delay = sop_begin_discovery(i, &snapshot);
        } else if (snapshot.phase == SOP_SLOT_SUBSCRIPTION_READY) {
            retry_delay = sop_begin_subscription(i, &snapshot);
        }

        bt_conn_unref(snapshot.conn);

        if (retry_delay != 0U && (next_retry == 0U || retry_delay < next_retry)) {
            next_retry = retry_delay;
        }
    }

    if (next_retry != 0U) {
        sop_schedule_discovery(next_retry);
    }
}

static void sop_connected(struct bt_conn *conn, uint8_t conn_err) {
    struct bt_conn_info info;
    if (conn_err || bt_conn_get_info(conn, &info) != 0 || info.role != BT_CONN_ROLE_CENTRAL) {
        /* Only the inter-half link, on which we are the BLE central, matters. */
        return;
    }

    struct bt_conn *owned_conn = bt_conn_ref(conn);
    if (owned_conn == NULL) {
        LOG_WRN("soft-off-plus: failed to retain peripheral connection");
        return;
    }

    bool reserved = false;
    bool already_tracked;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    already_tracked = sop_slot_for_conn_locked(conn) != NULL;
    if (!already_tracked) {
        for (int i = 0; i < ZMK_SPLIT_BLE_PERIPHERAL_COUNT; i++) {
            struct sop_peripheral_slot *slot = &peripherals[i];
            if (slot->conn != NULL) {
                continue;
            }

            /* Start every connection with fresh GATT procedure state. In
             * particular, Zephyr uses sub_discover_params.func as its
             * "auto-CCC discovery in progress" marker, so it must not leak
             * from a failed procedure on the previous connection. */
            memset(&slot->discover_params, 0, sizeof(slot->discover_params));
            memset(&slot->sub_discover_params, 0, sizeof(slot->sub_discover_params));
            memset(&slot->subscribe_params, 0, sizeof(slot->subscribe_params));
            slot->generation++;
            if (slot->generation == 0U) {
                slot->generation = 1U;
            }
            slot->off_handle = 0U;
            slot->phase = SOP_SLOT_WAIT_SECURITY;
            sop_reset_retry_locked(slot);
            slot->conn = owned_conn;
            reserved = true;
            break;
        }
    }
    k_spin_unlock(&sop_slots_lock, key);

    if (!reserved) {
        bt_conn_unref(owned_conn);
        if (!already_tracked) {
            /* Keep the warning separate from the locked region. */
            LOG_WRN("soft-off-plus: no free peripheral slot");
        }
        return;
    }

    /* Defer discovery so it does not race ZMK's connect-time discovery. */
    sop_schedule_discovery(SOP_DISCOVER_RETRY_MS);
}

static void sop_security_changed(struct bt_conn *conn, bt_security_t level,
                                 enum bt_security_err err) {
    bool ready = false;

    /* Once the link is encrypted, discovery can proceed; nudge the work item. */
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);
    if (slot != NULL && !err && level >= BT_SECURITY_L2 &&
        slot->phase == SOP_SLOT_WAIT_SECURITY) {
        slot->phase = SOP_SLOT_DISCOVERY_READY;
        sop_reset_retry_locked(slot);
        ready = true;
    }
    k_spin_unlock(&sop_slots_lock, key);

    if (ready) {
        sop_schedule_discovery(50U);
    }
}

static void sop_disconnected(struct bt_conn *conn, uint8_t reason) {
    ARG_UNUSED(reason);

    struct bt_conn *owned_conn = NULL;
    k_spinlock_key_t key = k_spin_lock(&sop_slots_lock);
    struct sop_peripheral_slot *slot = sop_slot_for_conn_locked(conn);
    if (slot != NULL) {
        owned_conn = slot->conn;
        slot->conn = NULL;
        slot->generation++;
        slot->phase = SOP_SLOT_EMPTY;
        slot->off_handle = 0U;
        sop_reset_retry_locked(slot);
    }
    k_spin_unlock(&sop_slots_lock, key);

    /* Zephyr has already torn down ATT requests and volatile subscriptions by
     * this callback. Do not call GATT cancellation APIs here; simply release
     * the slot's owning reference after invalidating every snapshot. */
    if (owned_conn != NULL) {
        bt_conn_unref(owned_conn);
    }
}

static struct bt_conn_cb sop_conn_callbacks = {
    .connected = sop_connected,
    .disconnected = sop_disconnected,
    .security_changed = sop_security_changed,
};

static int sop_central_init(void) {
    bt_conn_cb_register(&sop_conn_callbacks);
    return 0;
}
SYS_INIT(sop_central_init, APPLICATION, CONFIG_ZMK_BLE_INIT_PRIORITY);

static int sop_central_send(uint8_t cmd) {
    int sent = 0;

    for (int i = 0; i < ZMK_SPLIT_BLE_PERIPHERAL_COUNT; i++) {
        struct sop_slot_snapshot snapshot;
        if (!sop_snapshot_slot(i, &snapshot)) {
            continue;
        }

        if (snapshot.off_handle == 0U) {
            bt_conn_unref(snapshot.conn);
            continue;
        }

        int err = bt_gatt_write_without_response(snapshot.conn, snapshot.off_handle, &cmd,
                                                 sizeof(cmd), false);
        bt_conn_unref(snapshot.conn);
        if (err) {
            LOG_WRN("soft-off-plus: cmd 0x%02x write to peripheral %d failed (%d)", cmd, i, err);
        } else {
            sent++;
        }
    }

    return sent > 0 ? 0 : -ENOTCONN;
}

int zmk_soft_off_plus_signal_peers(void) { return sop_central_send(ZMK_SOFT_OFF_PLUS_CMD_OFF); }

int zmk_soft_off_plus_signal_peers_drop(void) {
    return sop_central_send(ZMK_SOFT_OFF_PLUS_CMD_DROP);
}

#else /* split peripheral */

/* ---------------------------------------------------------------------------
 * Peripheral: GATT server. The central writes the off command; we notify the
 * central when our own soft-off-plus is triggered.
 * ------------------------------------------------------------------------- */

static uint8_t sop_cmd_value;

static ssize_t sop_write_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf,
                            uint16_t len, uint16_t offset, uint8_t flags) {
    ARG_UNUSED(conn);
    ARG_UNUSED(attr);
    ARG_UNUSED(offset);
    ARG_UNUSED(flags);
    if (len >= 1) {
        sop_handle_cmd(((const uint8_t *)buf)[0]);
    }
    return len;
}

BT_GATT_SERVICE_DEFINE(
    sop_svc, BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_128(ZMK_SOFT_OFF_PLUS_SVC_UUID)),
    BT_GATT_CHARACTERISTIC(BT_UUID_DECLARE_128(ZMK_SOFT_OFF_PLUS_CHRC_UUID),
                           BT_GATT_CHRC_WRITE_WITHOUT_RESP | BT_GATT_CHRC_NOTIFY,
                           BT_GATT_PERM_WRITE_ENCRYPT, NULL, sop_write_cb, &sop_cmd_value),
    BT_GATT_CCC(NULL, BT_GATT_PERM_READ_ENCRYPT | BT_GATT_PERM_WRITE_ENCRYPT), );

static int sop_peripheral_send(uint8_t cmd) {
    /* attrs[1] is the characteristic declaration; bt_gatt_notify resolves the
     * value attribute from it. */
    int err = bt_gatt_notify(NULL, &sop_svc.attrs[1], &cmd, sizeof(cmd));
    if (err) {
        LOG_WRN("soft-off-plus: notify central (cmd 0x%02x) failed (%d)", cmd, err);
    }
    return err;
}

int zmk_soft_off_plus_signal_peers(void) { return sop_peripheral_send(ZMK_SOFT_OFF_PLUS_CMD_OFF); }

int zmk_soft_off_plus_signal_peers_drop(void) {
    return sop_peripheral_send(ZMK_SOFT_OFF_PLUS_CMD_DROP);
}

#endif /* role */

#endif /* CONFIG_ZMK_SOFT_OFF_PLUS_SPLIT_SYNC */
