"use client";

import { useCallback, useEffect, useState } from "react";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface ProcessingJob {
  id: string;
  case_id: string;
  evidence_id: string;
  adapter_name: string;
  adapter_version: string;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  result: Record<string, unknown> | null;
  error_code: string | null;
  attempt_count: number;
  max_attempts: number;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
}

async function requestJson<T>(
  path: string,
  init?: RequestInit,
  csrfToken?: string,
): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.method && init.method !== "GET" && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...init,
    headers,
  });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const detail =
      typeof body === "object" &&
      body !== null &&
      "detail" in body &&
      typeof body.detail === "string"
        ? body.detail
        : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

function formatTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
}

export default function ProcessingJobsPanel({
  caseId,
  evidenceId,
  csrfToken,
  canWrite,
}: {
  caseId: string;
  evidenceId: string;
  csrfToken: string;
  canWrite: boolean;
}) {
  const [jobs, setJobs] = useState<ProcessingJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const reload = useCallback(
    async (signal?: AbortSignal) => {
      const results = await requestJson<ProcessingJob[]>(
        `/cases/${encodeURIComponent(caseId)}/processing-jobs`,
        { signal },
      );
      if (!signal?.aborted) {
        setJobs(results.filter((job) => job.evidence_id === evidenceId));
        setError("");
      }
    },
    [caseId, evidenceId],
  );

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        await reload(controller.signal);
      } catch (caught) {
        if (!controller.signal.aborted) {
          setError(caught instanceof Error ? caught.message : "Could not load processing jobs.");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [reload]);

  async function createVerificationJob() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<ProcessingJob>(
        `/cases/${encodeURIComponent(caseId)}/processing-jobs`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            evidence_id: evidenceId,
            adapter_name: "custody-chain-verification",
          }),
        },
        csrfToken,
      );
      setNotice("Custody-chain verification job queued.");
      try {
        await reload();
      } catch (caught) {
        setError(
          `Job was queued, but the job list could not be refreshed: ${
            caught instanceof Error ? caught.message : "request failed"
          }`,
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not queue the verification job.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelJob(jobId: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await requestJson<ProcessingJob>(
        `/processing-jobs/${encodeURIComponent(jobId)}/cancel`,
        { method: "POST" },
        csrfToken,
      );
      setNotice("Queued job cancelled.");
      try {
        await reload();
      } catch (caught) {
        setError(
          `Job was cancelled, but the job list could not be refreshed: ${
            caught instanceof Error ? caught.message : "request failed"
          }`,
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not cancel the job.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Processing jobs" className="border-t border-slate-800 pt-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-white">Processing jobs</h3>
          <p className="mt-1 text-xs text-slate-500">
            Only custody-chain verification is available. Metadata parsing remains disabled pending independent sandbox validation.
          </p>
        </div>
        <button
          className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200 disabled:opacity-50"
          disabled={loading || busy}
          onClick={() => void reload().catch((caught: unknown) =>
            setError(caught instanceof Error ? caught.message : "Could not refresh jobs."),
          )}
          type="button"
        >
          Refresh
        </button>
      </div>
      {error && (
        <p className="mt-3 rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-xs text-rose-200" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="mt-3 rounded-lg border border-emerald-900 bg-emerald-950/50 p-3 text-xs text-emerald-200" role="status">
          {notice}
        </p>
      )}
      {canWrite && (
        <button
          className="mt-3 rounded-lg border border-cyan-800 px-3 py-2 text-xs font-medium text-cyan-200 disabled:opacity-50"
          disabled={busy}
          onClick={() => void createVerificationJob()}
          type="button"
        >
          Queue custody-chain verification
        </button>
      )}
      {loading ? (
        <p className="mt-3 text-xs text-slate-400">Loading jobs…</p>
      ) : jobs.length === 0 ? (
        <p className="mt-3 text-xs text-slate-500">No processing jobs for this evidence.</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {jobs.map((job) => (
            <li className="rounded border border-slate-800 p-3 text-xs" key={job.id}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-slate-200">
                  {job.adapter_name} · {job.status}
                </span>
                <span className="text-slate-500">
                  {formatTime(job.updated_at)}
                </span>
              </div>
              {job.result && (
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2 text-[11px] text-slate-300">
                  {JSON.stringify(job.result, null, 2)}
                </pre>
              )}
              {job.error_code && (
                <p className="mt-2 text-rose-300">Error: {job.error_code}</p>
              )}
              <p className="mt-2 text-slate-500">
                Attempts: {job.attempt_count}/{job.max_attempts}
              </p>
              {canWrite && job.status === "queued" && (
                <button
                  className="mt-2 rounded border border-rose-900 px-2 py-1 text-rose-200 disabled:opacity-50"
                  disabled={busy}
                  onClick={() => void cancelJob(job.id)}
                  type="button"
                >
                  Cancel queued job
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
