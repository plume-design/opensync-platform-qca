/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

struct osw_plat_qsdk_jobqueue
{
    struct osw_plat_qsdk11_4_async async;
    struct osw_plat_qsdk11_4_async **jobs;
    size_t n_jobs;
    char *name;
};

#define LOG_PREFIX_JOBQUEUE(ctx, fmt, ...) LOG_PREFIX("jobqueue: %s: " fmt, (ctx)->name, ##__VA_ARGS__)

static enum osw_plat_qsdk11_4_async_result osw_plat_qsdk_jobqueue_poll_cb(
        void *priv,
        struct osw_plat_qsdk11_4_cb *waker)
{
    struct osw_plat_qsdk_jobqueue *ctx = priv;
    bool done = true;
    size_t n_ready = 0;
    size_t i;

    for (i = 0; i < ctx->n_jobs; i++)
    {
        const enum osw_plat_qsdk11_4_async_result r = osw_plat_qsdk11_4_async_poll(ctx->jobs[i], waker);
        switch (r)
        {
            case OSW_PLAT_QSDK11_4_ASYNC_READY:
                LOGD(LOG_PREFIX_JOBQUEUE(ctx, "job #%zu out of %zu: ready", i, ctx->n_jobs));
                osw_plat_qsdk11_4_async_drop_safe(&ctx->jobs[i]);
                n_ready++;
                break;
            case OSW_PLAT_QSDK11_4_ASYNC_PENDING:
                done = false;
                break;
        }
    }

    if (done)
    {
        LOGD(LOG_PREFIX_JOBQUEUE(ctx, "ready"));
        return OSW_PLAT_QSDK11_4_ASYNC_READY;
    }
    else
    {
        LOGT(LOG_PREFIX_JOBQUEUE(ctx, "pending: %zu out of %zu ready", n_ready, ctx->n_jobs));
        return OSW_PLAT_QSDK11_4_ASYNC_PENDING;
    }
}

static void osw_plat_qsdk_jobqueue_drop_cb(void *priv)
{
    struct osw_plat_qsdk_jobqueue *ctx = priv;

    LOGT(LOG_PREFIX_JOBQUEUE(ctx, "dropping"));

    size_t i;
    for (i = 0; i < ctx->n_jobs; i++)
    {
        LOGT(LOG_PREFIX_JOBQUEUE(ctx, "dropping job #%zu out of %zu", i, ctx->n_jobs));
        osw_plat_qsdk11_4_async_drop_safe(&ctx->jobs[i]);
    }

    FREE(ctx->jobs);
    FREE(ctx->name);
    FREE(ctx);
}

static struct osw_plat_qsdk11_4_async *osw_plat_qsdk_jobqueue_alloc(
        const char *name,
        struct osw_plat_qsdk11_4_async **jobs,
        size_t n_jobs)
{
    struct osw_plat_qsdk_jobqueue *ctx = CALLOC(1, sizeof(*ctx));
    static const struct osw_plat_qsdk11_4_async_ops ops = {
        .poll_fn = osw_plat_qsdk_jobqueue_poll_cb,
        .drop_fn = osw_plat_qsdk_jobqueue_drop_cb,
    };
    ctx->name = STRDUP(name);
    ctx->jobs = jobs;
    ctx->n_jobs = n_jobs;
    LOGT(LOG_PREFIX_JOBQUEUE(ctx, "allocated"));
    return osw_plat_qsdk11_4_async_impl(&ops, ctx);
}

static struct osw_plat_qsdk11_4_async **osw_plat_qsdk_jobqueue_prep(
        struct osw_plat_qsdk11_4_async **jobs,
        size_t *n_jobs,
        struct osw_plat_qsdk11_4_async *job)
{
    const size_t elem_size = sizeof(job);
    const size_t elem_count = *n_jobs + 1;
    const size_t new_size = elem_count * elem_size;
    jobs = REALLOC(jobs, new_size);
    jobs[*n_jobs] = job;
    (*n_jobs)++;
    return jobs;
}
