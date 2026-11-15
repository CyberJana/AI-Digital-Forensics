"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

interface EvidenceRecord {
  id: string;
  evidence_number: string;
  name: string;
  size_bytes: number;
  original_sha256: string;
  binary_available: boolean;
  created_at: string;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = units[0];
  for (let index = 1; size >= 1024 && index < units.length; index += 1) {
    size /= 1024;
    unit = units[index];
  }
  return `${size.toFixed(1)} ${unit}`;
}

function localDateTimeValue(): string {
  const date = new Date(Date.now() - new Date().getTimezoneOffset() * 60_000);
  return date.toISOString().slice(0, 16);
}

async function errorDetail(response: Response): Promise<string> {
  const body: unknown = await response.json().catch(() => null);
  return typeof body === "object" &&
    body !== null &&
    "detail" in body &&
    typeof body.detail === "string"
    ? body.detail
    : `Request failed (${response.status})`;
}

export default function EvidenceStoragePanel({
  caseId,
  caseStatus,
  csrfToken,
  canWrite,
}: {
  caseId: string;
  caseStatus: string;
  csrfToken: string;
  canWrite: boolean;
}) {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [acquiredAt, setAcquiredAt] = useState(localDateTimeValue);

  const reload = useCallback(async (signal?: AbortSignal) => {
    setError("");
    try {
      const response = await fetch(`${API_BASE_URL}/cases/${caseId}/evidence`, {
        credentials: "include",
        signal,
      });
      if (!response.ok) throw new Error(await errorDetail(response));
      const records = (await response.json()) as EvidenceRecord[];
      if (!signal?.aborted) setEvidence(records);
    } catch (caught) {
      if (!signal?.aborted) {
        setError(caught instanceof Error ? caught.message : "Could not load evidence.");
      }
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setEvidence([]);
    void reload(controller.signal);
    return () => controller.abort();
  }, [reload]);

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = event.currentTarget;
    const formData = new FormData(form);
    formData.set("acquired_at", new Date(acquiredAt).toISOString());
    try {
      const response = await fetch(
        `${API_BASE_URL}/cases/${caseId}/evidence/upload`,
        {
          method: "POST",
          credentials: "include",
          headers: { "X-CSRF-Token": csrfToken },
          body: formData,
        },
      );
      if (!response.ok) throw new Error(await errorDetail(response));
      form.reset();
      setAcquiredAt(localDateTimeValue());
      await reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Evidence upload failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-labelledby="evidence-storage-heading"
      className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 md:p-6"
    >
      <p className="text-xs font-semibold tracking-wide text-cyan-300">
        ENCRYPTED EVIDENCE
      </p>
      <h2
        className="mt-1 text-lg font-semibold text-white"
        id="evidence-storage-heading"
      >
        Evidence files
      </h2>
      <p className="mt-2 text-sm leading-6 text-slate-400">
        Uploaded files are hashed by the server, encrypted with a per-file key, and
        stored as ciphertext. Downloads are integrity-checked before any file bytes
        are returned.
      </p>
      {error && (
        <p
          className="mt-4 rounded-lg border border-rose-900 bg-rose-950/50 p-3 text-sm text-rose-200"
          role="alert"
        >
          {error}
        </p>
      )}
      {canWrite && caseStatus === "open" && (
        <form
          className="mt-5 grid gap-3 border-b border-slate-800 pb-5 md:grid-cols-2"
          onSubmit={(event) => void upload(event)}
        >
          <label className="text-xs text-slate-400">
            Evidence number
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              maxLength={64}
              name="evidence_number"
              pattern="[A-Za-z0-9._-]+"
              required
            />
          </label>
          <label className="text-xs text-slate-400">
            Name
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              maxLength={200}
              name="name"
              required
            />
          </label>
          <label className="text-xs text-slate-400">
            Acquisition method
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              maxLength={100}
              name="acquisition_method"
              required
            />
          </label>
          <label className="text-xs text-slate-400">
            Source description
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              maxLength={1000}
              name="source_description"
              required
            />
          </label>
          <label className="text-xs text-slate-400">
            Acquisition time
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              onChange={(event) => setAcquiredAt(event.target.value)}
              required
              type="datetime-local"
              value={acquiredAt}
            />
          </label>
          <label className="text-xs text-slate-400">
            Evidence file
            <input
              className="mt-1 block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-700 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-white"
              name="file"
              required
              type="file"
            />
          </label>
          <label className="text-xs text-slate-400 md:col-span-2">
            Description (optional)
            <textarea
              className="mt-1 min-h-20 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              maxLength={4000}
              name="description"
            />
          </label>
          <div className="md:col-span-2">
            <button
              className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
              disabled={busy}
              type="submit"
            >
              {busy ? "Encrypting and uploading…" : "Upload and register evidence"}
            </button>
          </div>
        </form>
      )}
      {loading ? (
        <p className="mt-4 text-sm text-slate-400">Loading evidence…</p>
      ) : evidence.length === 0 ? (
        <p className="mt-4 text-sm text-slate-400">No evidence is registered.</p>
      ) : (
        <ul className="mt-4 divide-y divide-slate-800">
          {evidence.map((item) => (
            <li
              className="flex flex-wrap items-center justify-between gap-3 py-3"
              key={item.id}
            >
              <div className="min-w-0">
                <p className="font-medium text-white">
                  {item.evidence_number} · {item.name}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {formatBytes(item.size_bytes)} · SHA-256 {item.original_sha256}
                </p>
              </div>
              {item.binary_available ? (
                <a
                  className="rounded-lg border border-cyan-800 px-3 py-2 text-xs font-medium text-cyan-200 hover:border-cyan-400"
                  href={`${API_BASE_URL}/evidence/${item.id}/binary`}
                >
                  Download verified file
                </a>
              ) : (
                <span className="text-xs text-slate-500">Metadata only</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
