#include "queue.h"
#include "vhci.h"
#include "../apple_bce.h"

#define BCE_VHCI_CMD_PORT_RESUME_ID 0x12

static void bce_vhci_message_queue_completion(struct bce_queue_sq *sq);

int bce_vhci_message_queue_create(struct bce_vhci *vhci, struct bce_vhci_message_queue *ret, const char *name)
{
    int status;
    ret->cq = bce_create_cq(vhci->dev, VHCI_EVENT_QUEUE_EL_COUNT);
    if (!ret->cq)
        return -EINVAL;
    ret->sq = bce_create_sq(vhci->dev, ret->cq, name, VHCI_EVENT_QUEUE_EL_COUNT, DMA_TO_DEVICE,
                            bce_vhci_message_queue_completion, ret);
    if (!ret->sq) {
        status = -EINVAL;
        goto fail_cq;
    }
    ret->data = dma_alloc_coherent(&vhci->dev->pci->dev, sizeof(struct bce_vhci_message) * VHCI_EVENT_QUEUE_EL_COUNT,
                                   &ret->dma_addr, GFP_KERNEL);
    if (!ret->data) {
        status = -EINVAL;
        goto fail_sq;
    }
    return 0;

fail_sq:
    bce_destroy_sq(vhci->dev, ret->sq);
    ret->sq = NULL;
fail_cq:
    bce_destroy_cq(vhci->dev, ret->cq);
    ret->cq = NULL;
    return status;
}

void bce_vhci_message_queue_destroy(struct bce_vhci *vhci, struct bce_vhci_message_queue *q)
{
    if (!q->cq)
        return;
    dma_free_coherent(&vhci->dev->pci->dev, sizeof(struct bce_vhci_message) * VHCI_EVENT_QUEUE_EL_COUNT,
                      q->data, q->dma_addr);
    bce_destroy_sq(vhci->dev, q->sq);
    bce_destroy_cq(vhci->dev, q->cq);
}

void bce_vhci_message_queue_write(struct bce_vhci_message_queue *q, struct bce_vhci_message *req)
{
    int sidx;
    struct bce_qe_submission *s;
    sidx = q->sq->tail;
    s = bce_next_submission(q->sq);
    pr_debug("bce-vhci: Send message: %x s=%x p1=%x p2=%llx\n", req->cmd, req->status, req->param1, req->param2);
    q->data[sidx] = *req;
    bce_set_submission_single(s, q->dma_addr + sizeof(struct bce_vhci_message) * sidx,
            sizeof(struct bce_vhci_message));
    bce_submit_to_device(q->sq);
}

static void bce_vhci_message_queue_completion(struct bce_queue_sq *sq)
{
    while (bce_next_completion(sq))
        bce_notify_submission_complete(sq);
}



static void bce_vhci_event_queue_completion(struct bce_queue_sq *sq);

int __bce_vhci_event_queue_create(struct bce_vhci *vhci, struct bce_vhci_event_queue *ret, const char *name,
                                  bce_sq_completion compl)
{
    ret->vhci = vhci;

    ret->sq = bce_create_sq(vhci->dev, vhci->ev_cq, name, VHCI_EVENT_QUEUE_EL_COUNT, DMA_FROM_DEVICE, compl, ret);
    if (!ret->sq)
        return -EINVAL;
    ret->data = dma_alloc_coherent(&vhci->dev->pci->dev, sizeof(struct bce_vhci_message) * VHCI_EVENT_QUEUE_EL_COUNT,
                                   &ret->dma_addr, GFP_KERNEL);
    if (!ret->data) {
        bce_destroy_sq(vhci->dev, ret->sq);
        ret->sq = NULL;
        return -EINVAL;
    }

    init_completion(&ret->queue_empty_completion);
    bce_vhci_event_queue_submit_pending(ret, VHCI_EVENT_PENDING_COUNT);
    return 0;
}

int bce_vhci_event_queue_create(struct bce_vhci *vhci, struct bce_vhci_event_queue *ret, const char *name,
        bce_vhci_event_queue_callback cb)
{
    ret->cb = cb;
    return __bce_vhci_event_queue_create(vhci, ret, name, bce_vhci_event_queue_completion);
}

void bce_vhci_event_queue_destroy(struct bce_vhci *vhci, struct bce_vhci_event_queue *q)
{
    if (!q->sq)
        return;
    dma_free_coherent(&vhci->dev->pci->dev, sizeof(struct bce_vhci_message) * VHCI_EVENT_QUEUE_EL_COUNT,
                      q->data, q->dma_addr);
    bce_destroy_sq(vhci->dev, q->sq);
}

static void bce_vhci_event_queue_completion(struct bce_queue_sq *sq)
{
    struct bce_sq_completion_data *cd;
    struct bce_vhci_event_queue *ev = sq->userdata;
    struct bce_vhci_message *msg;
    size_t cnt = 0;

    while ((cd = bce_next_completion(sq))) {
        if (cd->status == BCE_COMPLETION_ABORTED) { /* We flushed the queue */
            bce_notify_submission_complete(sq);
            continue;
        }
        msg = &ev->data[sq->head];
        pr_debug("bce-vhci: Got event: %x s=%x p1=%x p2=%llx\n", msg->cmd, msg->status, msg->param1, msg->param2);
        ev->cb(ev, msg);

        bce_notify_submission_complete(sq);
        ++cnt;
    }
    bce_vhci_event_queue_submit_pending(ev, cnt);
    if (atomic_read(&sq->available_commands) == sq->el_count - 1)
        complete(&ev->queue_empty_completion);
}

void bce_vhci_event_queue_submit_pending(struct bce_vhci_event_queue *q, size_t count)
{
    int idx;
    struct bce_qe_submission *s;
    while (count--) {
        if (bce_reserve_submission(q->sq, NULL)) {
            pr_err("bce-vhci: Failed to reserve an event queue submission\n");
            break;
        }
        idx = q->sq->tail;
        s = bce_next_submission(q->sq);
        bce_set_submission_single(s,
                                  q->dma_addr + idx * sizeof(struct bce_vhci_message), sizeof(struct bce_vhci_message));
    }
    bce_submit_to_device(q->sq);
}

void bce_vhci_event_queue_pause(struct bce_vhci_event_queue *q)
{
    unsigned long timeout;
    reinit_completion(&q->queue_empty_completion);
    if (bce_cmd_flush_memory_queue(q->vhci->dev->cmd_cmdq, q->sq->qid))
        pr_warn("bce-vhci: failed to flush event queue\n");
    timeout = msecs_to_jiffies(5000);
    while (atomic_read(&q->sq->available_commands) != q->sq->el_count - 1) {
        timeout = wait_for_completion_timeout(&q->queue_empty_completion, timeout);
        if (timeout == 0) {
            pr_err("bce-vhci: waiting for queue to be flushed timed out\n");
            break;
        }
    }
}

void bce_vhci_event_queue_resume(struct bce_vhci_event_queue *q)
{
    if (atomic_read(&q->sq->available_commands) != q->sq->el_count - 1) {
        pr_err("bce-vhci: resume of a queue with pending submissions\n");
        return;
    }
    bce_vhci_event_queue_submit_pending(q, VHCI_EVENT_PENDING_COUNT);
}

static bool bce_vhci_completion_matches(struct bce_vhci_message *msg, u16 cmd, u32 param1)
{
    u16 rx_cmd = (u16) (msg->cmd & ~0x8000u);
    return rx_cmd == cmd && msg->param1 == param1;
}

static void bce_vhci_command_queue_dump_pending_locked(struct bce_vhci_command_queue_completion *c,
                                                       const char *reason)
{
    u16 pos;

    pr_info("bce-vhci: pending dump (%s): count=%u exp=%x/%x waiting=%d\n",
            reason ? reason : "no reason",
            c->pending_count, c->expected_cmd, c->expected_param1, c->waiting);
    for (pos = 0; pos < c->pending_count; pos++) {
        u16 i = (u16) ((c->pending_head + pos) % VHCI_CMD_PENDING_COUNT);
        struct bce_vhci_message *m = &c->pending[i];
        pr_info("bce-vhci: pending[%u] cmd=%x rx=%x st=%x p1=%x p2=%llx\n",
                pos, m->cmd, (u16) (m->cmd & ~0x8000u), m->status, m->param1,
                (unsigned long long) m->param2);
    }
}

static void bce_vhci_command_queue_clear_pending_locked(struct bce_vhci_command_queue_completion *c,
                                                        const char *reason)
{
    if (c->pending_count)
        pr_info("bce-vhci: cleared %u pending completions (%s)\n", c->pending_count,
                reason ? reason : "no reason");
    c->pending_head = 0;
    c->pending_count = 0;
}

void bce_vhci_command_queue_clear_pending(struct bce_vhci_command_queue *cq, const char *reason)
{
    spin_lock(&cq->completion_lock);
    bce_vhci_command_queue_clear_pending_locked(&cq->completion, reason);
    spin_unlock(&cq->completion_lock);
}

static void bce_vhci_command_queue_queue_pending(struct bce_vhci_command_queue_completion *c,
                                                 struct bce_vhci_message *msg)
{
    u16 idx;
    u16 rx_cmd = (u16) (msg->cmd & ~0x8000u);

    if (c->pending_count == VHCI_CMD_PENDING_COUNT) {
        c->pending_head = (u16) ((c->pending_head + 1) % VHCI_CMD_PENDING_COUNT);
        c->pending_count--;
        pr_warn("bce-vhci: pending completion queue full, dropping oldest\n");
    }

    idx = (u16) ((c->pending_head + c->pending_count) % VHCI_CMD_PENDING_COUNT);
    c->pending[idx] = *msg;
    c->pending_count++;
    pr_warn("bce-vhci: desync exp=%x/%x rx=%x/%x st=%x (queued=%u)\n",
            c->expected_cmd, c->expected_param1, rx_cmd, msg->param1, msg->status, c->pending_count);
}

static bool bce_vhci_command_queue_take_pending_match(struct bce_vhci_command_queue_completion *c,
                                                      u16 expected_cmd, u32 expected_param1,
                                                      struct bce_vhci_message *res)
{
    u16 pos;

    for (pos = 0; pos < c->pending_count; pos++) {
        u16 i = (u16) ((c->pending_head + pos) % VHCI_CMD_PENDING_COUNT);
        if (!bce_vhci_completion_matches(&c->pending[i], expected_cmd, expected_param1))
            continue;

        *res = c->pending[i];

        while (pos + 1 < c->pending_count) {
            u16 from = (u16) ((c->pending_head + pos + 1) % VHCI_CMD_PENDING_COUNT);
            u16 to = (u16) ((c->pending_head + pos) % VHCI_CMD_PENDING_COUNT);
            c->pending[to] = c->pending[from];
            pos++;
        }
        c->pending_count--;
        return true;
    }
    return false;
}

void bce_vhci_command_queue_create(struct bce_vhci_command_queue *ret, struct bce_vhci_message_queue *mq)
{
    ret->mq = mq;
    ret->completion.result = NULL;
    ret->completion.expected_cmd = 0;
    ret->completion.expected_param1 = 0;
    ret->completion.waiting = false;
    ret->completion.pending_head = 0;
    ret->completion.pending_count = 0;
    init_completion(&ret->completion.completion);
    spin_lock_init(&ret->completion_lock);
    mutex_init(&ret->mutex);
    pr_info("bce-vhci: command completion demux enabled (cmd+param1)\n");
}

void bce_vhci_command_queue_destroy(struct bce_vhci_command_queue *cq)
{
    spin_lock(&cq->completion_lock);
    if (cq->completion.result) {
        memset(cq->completion.result, 0, sizeof(struct bce_vhci_message));
        cq->completion.result->status = BCE_VHCI_ABORT;
        complete(&cq->completion.completion);
        cq->completion.result = NULL;
        cq->completion.waiting = false;
    }
    bce_vhci_command_queue_clear_pending_locked(&cq->completion, "command queue destroy");
    spin_unlock(&cq->completion_lock);
    mutex_lock(&cq->mutex);
    mutex_unlock(&cq->mutex);
    mutex_destroy(&cq->mutex);
}

void bce_vhci_command_queue_deliver_completion(struct bce_vhci_command_queue *cq, struct bce_vhci_message *msg)
{
    struct bce_vhci_command_queue_completion *c = &cq->completion;
    u16 rx_cmd = (u16) (msg->cmd & ~0x8000u);

    spin_lock(&cq->completion_lock);
    if (rx_cmd == BCE_VHCI_CMD_PORT_RESUME_ID) {
        pr_info("bce-vhci: cq rx PORT_RESUME completion cmd=%x st=%x p1=%x p2=%llx waiting=%d exp=%x/%x pending=%u\n",
                msg->cmd, msg->status, msg->param1, (unsigned long long) msg->param2,
                c->waiting, c->expected_cmd, c->expected_param1, c->pending_count);
    }
    if (c->result && c->waiting) {
        if (bce_vhci_completion_matches(msg, c->expected_cmd, c->expected_param1)) {
            *c->result = *msg;
            complete(&c->completion);
            c->result = NULL;
            c->waiting = false;
        } else {
            bce_vhci_command_queue_queue_pending(c, msg);
        }
    } else {
        bce_vhci_command_queue_queue_pending(c, msg);
    }
    spin_unlock(&cq->completion_lock);
}

static int __bce_vhci_command_queue_execute(struct bce_vhci_command_queue *cq, struct bce_vhci_message *req,
        struct bce_vhci_message *res, unsigned long timeout)
{
    int status;
    bool trace_port_resume = req->cmd == BCE_VHCI_CMD_PORT_RESUME_ID;
    struct bce_vhci_command_queue_completion *c;
    c = &cq->completion;

    if ((status = bce_reserve_submission(cq->mq->sq, &timeout)))
        return status;

    spin_lock(&cq->completion_lock);
    c->result = res;
    c->expected_cmd = req->cmd;
    c->expected_param1 = req->param1;
    c->waiting = true;
    reinit_completion(&c->completion);
    if (trace_port_resume) {
        pr_info("bce-vhci: cq send PORT_RESUME req(cmd=%x p1=%x p2=%llx) exp=%x/%x pending_before=%u\n",
                req->cmd, req->param1, (unsigned long long) req->param2,
                c->expected_cmd, c->expected_param1, c->pending_count);
        if (req->param1 == 6 && c->pending_count)
            bce_vhci_command_queue_dump_pending_locked(c, "before send port6");
    }
    spin_unlock(&cq->completion_lock);

    bce_vhci_message_queue_write(cq->mq, req);

    spin_lock(&cq->completion_lock);
    if (trace_port_resume && req->param1 == 6 && c->waiting && c->result) {
        pr_info("bce-vhci: cq waiting for PORT_RESUME p1=6 reply (pending=%u)\n",
                c->pending_count);
        if (c->pending_count)
            bce_vhci_command_queue_dump_pending_locked(c, "waiting port6");
    }
    if (c->waiting && c->result &&
        bce_vhci_command_queue_take_pending_match(c, c->expected_cmd, c->expected_param1, c->result)) {
        if (trace_port_resume) {
            pr_info("bce-vhci: cq PORT_RESUME p1=%x satisfied from pending res(cmd=%x st=%x p1=%x p2=%llx)\n",
                    req->param1, c->result->cmd, c->result->status, c->result->param1,
                    (unsigned long long) c->result->param2);
        }
        c->result = NULL;
        c->waiting = false;
        spin_unlock(&cq->completion_lock);
        goto got_reply;
    }
    spin_unlock(&cq->completion_lock);

    if (!wait_for_completion_timeout(&c->completion, timeout)) {
        pr_err("bce-vhci: command timeout cmd=%x p1=%x (waited %lu jiffies)\n",
               req->cmd, req->param1, timeout);
        bce_vhci_dump_recent_system_events(
                container_of(cq, struct bce_vhci, cq), req);

        /* Send cancel command to keep T2 state consistent */
        spin_lock(&cq->completion_lock);
        c->result = res;   /* reuse res for cancel response */
        c->expected_cmd = req->cmd | 0x4000;
        c->expected_param1 = req->param1;
        reinit_completion(&c->completion);
        spin_unlock(&cq->completion_lock);

        if (!bce_reserve_submission(cq->mq->sq, NULL)) {
            struct bce_vhci_message creq = *req;
            creq.cmd |= 0x4000;
            bce_vhci_message_queue_write(cq->mq, &creq);

            if (!wait_for_completion_timeout(&c->completion,
                                             msecs_to_jiffies(1000))) {
                pr_err("bce-vhci: cmd cancel timed out, possible desync\n");
            }
        }

        spin_lock(&cq->completion_lock);
        c->result = NULL;
        c->waiting = false;
        spin_unlock(&cq->completion_lock);
        return -ETIMEDOUT;
    }
    if (trace_port_resume) {
        pr_info("bce-vhci: cq PORT_RESUME p1=%x completed res(cmd=%x st=%x p1=%x p2=%llx)\n",
                req->param1, res->cmd, res->status, res->param1, (unsigned long long) res->param2);
    }

got_reply:
    /* command queue shutdown path */
    if (res->status == BCE_VHCI_ABORT)
        return BCE_VHCI_ABORT;

    if (res->status == BCE_VHCI_SUCCESS)
        return 0;
    return res->status;
}

int bce_vhci_command_queue_execute(struct bce_vhci_command_queue *cq, struct bce_vhci_message *req,
                                   struct bce_vhci_message *res, unsigned long timeout)
{
    int status;
    mutex_lock(&cq->mutex);
    status = __bce_vhci_command_queue_execute(cq, req, res, timeout);
    mutex_unlock(&cq->mutex);
    return status;
}
