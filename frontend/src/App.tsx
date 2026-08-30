import { useCallback, useEffect, useState } from "react";
import {
  BACKEND_CANISTER_ID,
  call,
} from "./thebes";
import { useMemphis } from "./useMemphis";
import MemphisGate from "./MemphisGate";
type Note = {
  id: bigint;
  title: string;
  body: string;
};

const MAGIC = [0x44, 0x49, 0x44, 0x4c];

/* =========================================================
   Candid helpers
   ========================================================= */

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) =>
      byte.toString(16).padStart(2, "0")
    )
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const clean =
    hex.length % 2 === 0
      ? hex
      : `0${hex}`;

  const bytes = new Uint8Array(
    clean.length / 2
  );

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(
      clean.slice(i * 2, i * 2 + 2),
      16
    );
  }

  return bytes;
}

function uleb(value: bigint): number[] {
  const result: number[] = [];

  while (true) {
    const byte = Number(
      value & 0x7fn
    );

    value >>= 7n;

    if (value === 0n) {
      result.push(byte);
      return result;
    }

    result.push(byte | 0x80);
  }
}

function readUleb(
  bytes: Uint8Array,
  offset: number
): [bigint, number] {
  let result = 0n;
  let shift = 0n;

  while (true) {
    const byte = bytes[offset++];

    if (byte === undefined) {
      throw new Error(
        "Invalid Candid ULEB128"
      );
    }

    result |=
      BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      return [result, offset];
    }

    shift += 7n;
  }
}

function readSleb(
  bytes: Uint8Array,
  offset: number
): [bigint, number] {
  let result = 0n;
  let shift = 0n;

  while (true) {
    const byte = bytes[offset++];

    if (byte === undefined) {
      throw new Error(
        "Invalid Candid SLEB128"
      );
    }

    result |=
      BigInt(byte & 0x7f) << shift;

    shift += 7n;

    if ((byte & 0x80) === 0) {
      if ((byte & 0x40) !== 0) {
        result -= 1n << shift;
      }

      return [result, offset];
    }
  }
}

function readText(
  bytes: Uint8Array,
  offset: number
): [string, number] {
  const [length, nextOffset] =
    readUleb(bytes, offset);

  const end =
    nextOffset + Number(length);

  if (end > bytes.length) {
    throw new Error(
      "Invalid Candid text value"
    );
  }

  return [
    new TextDecoder().decode(
      bytes.slice(nextOffset, end)
    ),
    end,
  ];
}

function fieldHash(
  name: string
): number {
  const bytes =
    new TextEncoder().encode(name);

  let hash = 0;

  for (const byte of bytes) {
    hash =
      (hash * 223 + byte) >>> 0;
  }

  return hash;
}

/* =========================================================
   Candid encoders
   ========================================================= */

function encodeTextArg(value: string): number[] {
  const bytes = new TextEncoder().encode(value);
  return [
    ...MAGIC,
    0,
    1,
    0x71,
    ...uleb(BigInt(bytes.length)),
    ...bytes,
  ];
}
function encodeAddArgs(
  title: string,
  body: string,
  owner: string
): string {
  const titleBytes = new TextEncoder().encode(title);
  const bodyBytes = new TextEncoder().encode(body);
  const ownerBytes = new TextEncoder().encode(owner);

  return bytesToHex(new Uint8Array([
    ...MAGIC,
    0,
    3,
    0x71,
    0x71,
    0x71,
    ...uleb(BigInt(titleBytes.length)),
    ...titleBytes,
    ...uleb(BigInt(bodyBytes.length)),
    ...bodyBytes,
    ...uleb(BigInt(ownerBytes.length)),
    ...ownerBytes,
  ]));
}

function encodeEditArgs(
  id: bigint,
  title: string,
  body: string,
  owner: string
): string {
  const titleBytes = new TextEncoder().encode(title);
  const bodyBytes = new TextEncoder().encode(body);
  const ownerBytes = new TextEncoder().encode(owner);

  return bytesToHex(new Uint8Array([
    ...MAGIC,
    0,
    4,
    0x7d,
    0x71,
    0x71,
    0x71,
    ...uleb(id),
    ...uleb(BigInt(titleBytes.length)),
    ...titleBytes,
    ...uleb(BigInt(bodyBytes.length)),
    ...bodyBytes,
    ...uleb(BigInt(ownerBytes.length)),
    ...ownerBytes,
  ]));
}

function encodeRemoveArgs(
  id: bigint,
  owner: string
): string {
  const ownerBytes = new TextEncoder().encode(owner);

  return bytesToHex(new Uint8Array([
    ...MAGIC,
    0,
    2,
    0x7d,
    0x71,
    ...uleb(id),
    ...uleb(BigInt(ownerBytes.length)),
    ...ownerBytes,
  ]));
}

function encodeGetNotesArgs(owner: string): string {
  return bytesToHex(new Uint8Array(encodeTextArg(owner)));
}

/* =========================================================
   get_notes decoder
   ========================================================= */

function decodeNotes(
  hex: string
): Note[] {
  const bytes =
    hexToBytes(hex);

  if (
    bytes.length < 4 ||
    bytes[0] !== 0x44 ||
    bytes[1] !== 0x49 ||
    bytes[2] !== 0x44 ||
    bytes[3] !== 0x4c
  ) {
    throw new Error(
      "Invalid Candid magic"
    );
  }

  let offset = 4;

  const [
    typeTableLength,
    afterTypeTableLength,
  ] = readUleb(
    bytes,
    offset
  );

  offset =
    afterTypeTableLength;

  const types: Array<
    | {
      kind: "record";
      fields: Array<{
        hash: number;
        type: bigint;
      }>;
    }
    | {
      kind: "vec";
      elementType: bigint;
    }
  > = [];

  for (
    let i = 0;
    i < Number(typeTableLength);
    i++
  ) {
    const [
      typeCode,
      afterTypeCode,
    ] = readSleb(
      bytes,
      offset
    );

    offset = afterTypeCode;

    if (typeCode === -20n) {
      const [
        fieldCount,
        afterFieldCount,
      ] = readUleb(
        bytes,
        offset
      );

      offset = afterFieldCount;

      const fields: Array<{
        hash: number;
        type: bigint;
      }> = [];

      for (
        let j = 0;
        j < Number(fieldCount);
        j++
      ) {
        const [
          hash,
          afterHash,
        ] = readUleb(
          bytes,
          offset
        );

        offset = afterHash;

        const [
          fieldType,
          afterFieldType,
        ] = readSleb(
          bytes,
          offset
        );

        offset =
          afterFieldType;

        fields.push({
          hash: Number(hash),
          type: fieldType,
        });
      }

      types.push({
        kind: "record",
        fields,
      });
    } else if (typeCode === -19n) {
      const [
        elementType,
        afterElementType,
      ] = readSleb(
        bytes,
        offset
      );

      offset =
        afterElementType;

      types.push({
        kind: "vec",
        elementType,
      });
    } else {
      throw new Error(
        `Unsupported Candid type: ${typeCode}`
      );
    }
  }

  const [
    returnCount,
    afterReturnCount,
  ] = readUleb(
    bytes,
    offset
  );

  offset =
    afterReturnCount;

  if (returnCount !== 1n) {
    throw new Error(
      "get_notes() returned an unexpected number of values"
    );
  }

  const [
    returnType,
    afterReturnType,
  ] = readSleb(
    bytes,
    offset
  );

  offset =
    afterReturnType;

  if (returnType < 0n) {
    throw new Error(
      "get_notes() did not return a vector"
    );
  }

  const vec =
    types[Number(returnType)];

  if (
    !vec ||
    vec.kind !== "vec"
  ) {
    throw new Error(
      "get_notes() did not return a vector"
    );
  }

  const record =
    types[Number(vec.elementType)];

  if (
    !record ||
    record.kind !== "record"
  ) {
    throw new Error(
      "Invalid Note record type"
    );
  }

  const [
    count,
    afterCount,
  ] = readUleb(
    bytes,
    offset
  );

  offset = afterCount;

  const idHash =
    fieldHash("id");

  const titleHash =
    fieldHash("title");

  const bodyHash =
    fieldHash("body");

  const fields =
    [...record.fields].sort(
      (a, b) =>
        a.hash - b.hash
    );

  const notes: Note[] = [];

  for (
    let i = 0;
    i < Number(count);
    i++
  ) {
    let id = 0n;
    let title = "";
    let body = "";

    for (const field of fields) {
      if (field.hash === idHash) {
        [id, offset] =
          readUleb(
            bytes,
            offset
          );
      } else if (
        field.hash === titleHash
      ) {
        [title, offset] =
          readText(
            bytes,
            offset
          );
      } else if (
        field.hash === bodyHash
      ) {
        [body, offset] =
          readText(
            bytes,
            offset
          );
      } else {
        throw new Error(
          `Unknown Note field hash: ${field.hash}`
        );
      }
    }

    notes.push({
      id,
      title,
      body,
    });
  }

  return notes;
}

/* =========================================================
   get_notes
   ========================================================= */

async function getNotes(owner: string): Promise<Note[]> {
  const senderKey =
    `thebes-demo-sender:${BACKEND_CANISTER_ID}`;

  let sender =
    localStorage.getItem(
      senderKey
    );

  if (!sender) {
    const random =
      new Uint8Array(8);

    crypto.getRandomValues(
      random
    );

    sender =
      bytesToHex(random);

    localStorage.setItem(
      senderKey,
      sender
    );
  }

  const arg = encodeGetNotesArgs(owner);

  const response =
    await fetch(
      "/api/query",
      {
        method: "POST",
        headers: {
          "content-type":
            "application/json",
        },
        body: JSON.stringify({
          canister_id:
            BACKEND_CANISTER_ID,
          method: "get_notes",
          arg,
          sender,
        }),
      }
    );

  const text =
    await response.text();

  let json: any;

  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(
      `Malformed query response: ${text.slice(
        0,
        300
      )}`
    );
  }

  if (!response.ok) {
    throw new Error(
      json.error ||
      `HTTP ${response.status}`
    );
  }

  if (
    json.status !==
    "success"
  ) {
    throw new Error(
      json.error ||
      "get_notes() query failed"
    );
  }

  return decodeNotes(
    json.reply || ""
  );
}
/* =========================================================
   App
   ========================================================= */

function App() {
  const auth = useMemphis();

  const [notes, setNotes] =
    useState<Note[]>([]);

  const [title, setTitle] =
    useState("");

  const [body, setBody] =
    useState("");

  const [editingId, setEditingId] =
    useState<bigint | null>(null);

  const [isCreating, setIsCreating] =
    useState(false);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  const [darkMode, setDarkMode] =
    useState(() => localStorage.getItem("thebes-theme") === "dark");
  const owner = auth.session?.anchor_id_hex ?? "";

  const refresh = useCallback(async (o: string) => {
    setLoading(true);

    try {
      const hex = await getNotes(o);
      setNotes(hex);
      setError("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);



  useEffect(() => {
    if (!owner) {
      setNotes([]);
      setError("");
      setBody("");
      setTitle("");
      return;
    }

    void refresh(owner);
  }, [owner, refresh]);


  useEffect(() => {
    localStorage.setItem("thebes-theme", darkMode ? "dark" : "light");
  }, [darkMode]);

  /* -------------------------------------------------------
     Load
     ------------------------------------------------------- */

  async function loadNotes() {
    if (!owner) {
      setNotes([]);
      return;
    }
    try {
      setError("");

      const result =
        await getNotes(owner);

      setNotes(result);
    } catch (err) {
      console.error(err);

      setError(
        err instanceof Error
          ? err.message
          : String(err)
      );
    }
  }

  /* -------------------------------------------------------
     Create
     ------------------------------------------------------- */

  async function addNote() {
    if (!owner) {
      setError("Please sign in first.");
      return;
    }

    if (
      !title.trim() ||
      !body.trim()
    ) {
      return;
    }

    try {
      setLoading(true);
      setError("");

      try {
        await call(
          "add",
          encodeAddArgs(
            title,
            body, owner
          )
        );
      } catch (err) {
        console.warn(
          "add response:",
          err
        );
      }

      setTitle("");
      setBody("");
      setIsCreating(false);

      await loadNotes();
    } catch (err) {
      console.error(err);

      setError(
        err instanceof Error
          ? err.message
          : String(err)
      );
    } finally {
      setLoading(false);
    }
  }

  /* -------------------------------------------------------
     Edit
     ------------------------------------------------------- */

  async function editNote() {
    if (!owner) {
      setError("Please sign in first.");
      return;
    }
    if (
      editingId === null ||
      !title.trim() ||
      !body.trim()
    ) {
      return;
    }

    try {
      setLoading(true);
      setError("");

      try {
        await call(
          "edit",
          encodeEditArgs(
            editingId,
            title,
            body, owner
          )
        );
      } catch (err) {
        console.warn(
          "edit response:",
          err
        );
      }

      setEditingId(null);
      setIsCreating(false);
      setTitle("");
      setBody("");

      await loadNotes();
    } catch (err) {
      console.error(err);

      setError(
        err instanceof Error
          ? err.message
          : String(err)
      );
    } finally {
      setLoading(false);
    }
  }

  /* -------------------------------------------------------
     Delete
     ------------------------------------------------------- */

  async function removeNote(
    id: bigint
  ) {
    if (!owner) {
      setError("Please sign in first.");
      return;
    }
    try {
      setLoading(true);
      setError("");

      try {
        await call(
          "remove",
          encodeRemoveArgs(id, owner)
        );
      } catch (err) {
        console.warn(
          "remove response:",
          err
        );
      }

      await loadNotes();
    } catch (err) {
      console.error(err);

      setError(
        err instanceof Error
          ? err.message
          : String(err)
      );
    } finally {
      setLoading(false);
    }
  }

  /* -------------------------------------------------------
     Start creating
     ------------------------------------------------------- */

  function startCreating() {
    setEditingId(null);
    setIsCreating(true);
    setTitle("");
    setBody("");
    setError("");
  }

  /* -------------------------------------------------------
     Start editing
     ------------------------------------------------------- */

  function startEdit(
    note: Note
  ) {
    setIsCreating(false);
    setEditingId(note.id);
    setTitle(note.title);
    setBody(note.body);
    setError("");
  }

  /* -------------------------------------------------------
     Cancel
     ------------------------------------------------------- */

  function cancelEditor() {
    setEditingId(null);
    setIsCreating(false);
    setTitle("");
    setBody("");
    setError("");
  }

  /* -------------------------------------------------------
     Initial load
     ------------------------------------------------------- */

  useEffect(() => {
    void loadNotes();
  }, []);

  return (
    <div className={darkMode ? "app dark" : "app light"}>


      <style>{`
        * {
          box-sizing: border-box;
        }

        .app {
          min-height: 100vh;
          transition: background 0.2s ease, color 0.2s ease;
        }

        .app.dark {
          background: #171513;
          color: #f1ece7;
        }

        .app.light {
          background: #f8f7f4;
          color: #292522;
        }

        /* MemphisGate theme */
        .app.dark .panel.memphis {
          background: #211f1d;
          color: #f1ece7;
          border-color: #393531;
        }

        .app.dark .panel.memphis h2,
        .app.dark .panel.memphis p {
          color: #f1ece7;
        }

        .app.dark .panel.memphis .hint {
          color: #aaa19a;
        }

        .app.dark .panel.memphis input {
          background: #171513;
          color: #f1ece7;
          border-color: #514b45;
          caret-color: #f1ece7;
        }

        .app.dark .panel.memphis input::placeholder {
          color: #817a74;
        }

        .app.dark .panel.memphis button {
          background: #f1ece7;
          color: #292522;
          border-color: #f1ece7;
        }

        .app.dark .panel.memphis button:disabled {
          background: #393531;
          color: #817a74;
          border-color: #393531;
        }

        .app.dark .panel.memphis code {
          background: #2b2825;
          color: #d8d0c9;
        }

        .app.light .panel.memphis {
          background: white;
          color: #292522;
          border-color: #e7e2dc;
        }

        .app.light .panel.memphis input {
          background: white;
          color: #292522;
          border-color: #d8d1ca;
        }

        .app.light .panel.memphis input::placeholder {
          color: #9a9189;
        }

        .app.light .panel.memphis .hint {
          color: #817870;
        }

        .app.light .panel.memphis code {
          background: #f0ece8;
          color: #4b4540;
        }

        body {
          margin: 0;
          background: ${darkMode ? "#171513" : "#f8f7f4"};
          color: ${darkMode ? "#f1ece7" : "#292522"};
          font-family:
            Inter,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
          transition: background 0.2s ease, color 0.2s ease;
        }

        button,
        input,
        textarea {
          font: inherit;
        }

        button {
          transition:
            background 0.15s ease,
            transform 0.15s ease,
            opacity 0.15s ease;
        }

        button:not(:disabled):hover {
          transform: translateY(-1px);
        }

        button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .page {
          min-height: 100vh;
          padding: 45px 20px;
        }

        .container {
          max-width: 850px;
          margin: auto;
        }

        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 20px;
          margin-bottom: 35px;
        }

        .logo {
          font-family: Georgia, serif;
          font-size: 30px;
          font-weight: 600;
          letter-spacing: -1px;
        }

        .subtitle {
          color: ${darkMode ? "#a69d96" : "#8a8179"};
          font-size: 13px;
          margin-top: 4px;
        }

        .header-actions {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .theme-button {
          border: 1px solid ${darkMode ? "#514b45" : "#ddd6cf"};
          background: ${darkMode ? "#211f1d" : "white"};
          color: ${darkMode ? "#f1ece7" : "#4b4540"};
          padding: 9px 12px;
          border-radius: 8px;
          cursor: pointer;
          font-size: 12px;
          white-space: nowrap;
          transition:
            background 0.15s ease,
            border-color 0.15s ease,
            transform 0.15s ease;
        }

        .theme-button:hover {
          transform: translateY(-1px);
          background: ${darkMode ? "#2b2825" : "#f2efeb"};
        }

        .new-button {
          border: none;
          background: ${darkMode ? "#f1ece7" : "#292522"};
          color: ${darkMode ? "#292522" : "white"};
          padding: 10px 17px;
          border-radius: 8px;
          cursor: pointer;
          font-size: 13px;
          white-space: nowrap;
        }

        .new-button:hover {
          background: ${darkMode ? "#d9d1ca" : "#403a35"};
        }

        .editor {
          background: ${darkMode ? "#211f1d" : "white"};
          border: 1px solid ${darkMode ? "#393531" : "#e7e2dc"};
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 30px;
          box-shadow:
            0 5px 20px
            rgba(50, 40, 30, 0.04);
        }

        .editor-title {
          font-family: Georgia, serif;
          font-size: 19px;
          margin: 0 0 15px;
        }

        .input {
          width: 100%;
          border: none;
          outline: none;
          background: transparent;
          color: ${darkMode ? "#f1ece7" : "#292522"};
        }

        .title-input {
          font-family: Georgia, serif;
          font-size: 20px;
          padding: 8px 0;
          border-bottom:
            1px solid ${darkMode ? "#393531" : "#eee9e4"};
        }

        .body-input {
          min-height: 110px;
          resize: vertical;
          padding: 14px 0 5px;
          line-height: 1.6;
          font-size: 14px;
        }

        .editor-footer {
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          margin-top: 8px;
        }

        .cancel {
          border: none;
          background: transparent;
          color: ${darkMode ? "#aaa19a" : "#817870"};
          padding: 9px 13px;
          cursor: pointer;
        }

        .save {
          border: none;
          background: ${darkMode ? "#f1ece7" : "#292522"};
          color: ${darkMode ? "#292522" : "white"};
          padding: 9px 15px;
          border-radius: 7px;
          cursor: pointer;
          font-size: 13px;
        }

        .error {
          background: ${darkMode ? "#35201f" : "#fff0ef"};
          border:
            1px solid ${darkMode ? "#633b38" : "#f2d3d0"};
          color: ${darkMode ? "#f0aaa4" : "#9b4b44"};
          padding: 11px 14px;
          border-radius: 8px;
          margin-bottom: 20px;
          font-size: 13px;
          word-break: break-word;
        }

        .notes-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 15px;
        }

        .notes-title {
          font-family: Georgia, serif;
          font-size: 20px;
          margin: 0;
        }

        .notes-tools {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .count {
          color: ${darkMode ? "#9b928b" : "#a09790"};
          font-size: 12px;
        }

        .refresh {
          border: none;
          background: transparent;
          color: ${darkMode ? "#aaa19a" : "#8c837b"};
          cursor: pointer;
          font-size: 12px;
        }

        .notes {
          display: grid;
          grid-template-columns:
            repeat(2, minmax(0, 1fr));
          gap: 15px;
        }

        .note {
          background: ${darkMode ? "#211f1d" : "white"};
          border:
            1px solid ${darkMode ? "#393531" : "#e7e2dc"};
          border-radius: 11px;
          padding: 20px;
          min-height: 170px;
          display: flex;
          flex-direction: column;
          transition: 0.15s ease;
        }

        .note:hover {
          border-color: ${darkMode ? "#514b45" : "#d4cec7"};
          transform: translateY(-2px);
          box-shadow:
            0 8px 22px
            rgba(50, 40, 30, 0.05);
        }

        .note-head {
          display: flex;
          justify-content: space-between;
          gap: 10px;
        }

        .note-title {
          font-family: Georgia, serif;
          font-size: 18px;
          margin: 0;
          line-height: 1.3;
          word-break: break-word;
        }

        .note-body {
          color: ${darkMode ? "#b2aaa3" : "#716a64"};
          font-size: 13px;
          line-height: 1.65;
          margin: 11px 0 20px;
          white-space: pre-wrap;
          word-break: break-word;

          display: -webkit-box;
          -webkit-line-clamp: 5;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }

        .note-footer {
          margin-top: auto;
          padding-top: 12px;
          border-top:
            1px solid ${darkMode ? "#393531" : "#f0ece8"};
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .note-id {
          color: ${darkMode ? "#817a74" : "#b1aaa4"};
          font-size: 10px;
        }

        .actions {
          display: flex;
          gap: 5px;
        }

        .action {
          border: none;
          background: transparent;
          color: ${darkMode ? "#aaa19a" : "#8b837c"};
          padding: 4px 6px;
          cursor: pointer;
          font-size: 11px;
        }

        .action:hover {
          color: ${darkMode ? "#f1ece7" : "#292522"};
        }

        .delete:hover {
          color: #a34d47;
        }

        .empty {
          text-align: center;
          padding: 60px 20px;
          border:
            1px dashed ${darkMode ? "#514b45" : "#ddd6cf"};
          border-radius: 12px;
          color: ${darkMode ? "#9b928b" : "#958c84"};
        }

        .empty-icon {
          font-family: Georgia, serif;
          font-size: 30px;
          margin-bottom: 10px;
        }

        .empty-title {
          color: ${darkMode ? "#d0c8c1" : "#4b4540"};
          font-family: Georgia, serif;
          font-size: 17px;
          margin-bottom: 5px;
        }

        .empty-text {
          font-size: 12px;
        }

        @media (max-width: 650px) {
          .page {
            padding: 25px 15px;
          }

          .header {
            margin-bottom: 25px;
            flex-wrap: wrap;
          }

          .header-actions {
            width: 100%;
            justify-content: flex-end;
          }

          .logo {
            font-size: 26px;
          }

          .new-button {
            padding: 9px 12px;
          }

          .notes {
            grid-template-columns: 1fr;
          }
        }
      `}</style>

      <div className="page">
        <div className="container">

          {/* Header */}

          <header className="header">
            <div>
              <div className="logo">
                Thebes
              </div>

              <div className="subtitle">
                A simple place for your thoughts
              </div>
            </div>

            <div className="header-actions">
              <button
                className="theme-button"
                onClick={() => setDarkMode((value) => !value)}
                aria-label={
                  darkMode
                    ? "Switch to light mode"
                    : "Switch to dark mode"
                }
                title={
                  darkMode
                    ? "Switch to light mode"
                    : "Switch to dark mode"
                }
              >
                {darkMode ? "☀️ Light" : "🌙 Dark"}
              </button>
              {!auth.signIn ? (<div></div>
              ) : (!isCreating &&
                editingId === null && (
                  <button
                    className="new-button"
                    onClick={
                      startCreating
                    }
                  >
                    + New note
                  </button>
                ))}
            </div>
          </header>

          {/* Error */}

          {error && (
            <div className="error">
              {error}
            </div>
          )}
          <MemphisGate auth={auth} />
          {/* Editor */}

          {(isCreating ||
            editingId !== null) && (
              <section className="editor">
                <h2 className="editor-title">
                  {editingId !== null
                    ? "Edit note"
                    : "New note"}
                </h2>

                <input
                  className="input title-input"
                  value={title}
                  onChange={(event) =>
                    setTitle(
                      event.target.value
                    )
                  }
                  placeholder="Title"
                  disabled={loading}
                  autoFocus
                />

                <textarea
                  className="input body-input"
                  value={body}
                  onChange={(event) =>
                    setBody(
                      event.target.value
                    )
                  }
                  placeholder="Write something..."
                  disabled={loading}
                />

                <div className="editor-footer">
                  <button
                    className="cancel"
                    onClick={
                      cancelEditor
                    }
                    disabled={loading}
                  >
                    Cancel
                  </button>

                  <button
                    className="save"
                    onClick={
                      editingId !== null
                        ? editNote
                        : addNote
                    }
                    disabled={
                      loading ||
                      !title.trim() ||
                      !body.trim()
                    }
                  >
                    {loading
                      ? "Saving..."
                      : editingId !== null
                        ? "Save changes"
                        : "Save note"}
                  </button>
                </div>
              </section>
            )}

          {/* Notes header */}

          <div className="notes-header">
            <h2 className="notes-title">
              Your notes
            </h2>

            <div className="notes-tools">
              <span className="count">
                {notes.length}{" "}
                {notes.length === 1
                  ? "note"
                  : "notes"}
              </span>

              <button
                className="refresh"
                onClick={() =>
                  void loadNotes()
                }
                disabled={loading}
              >
                Refresh
              </button>
            </div>
          </div>

          {/* Notes */}
          {!auth.signIn ? (<div className="note-head">
            <h3 className="note-title">
              Please sign in to see your notes :3
            </h3>
          </div>
          ) : (
            notes.length === 0 ? (
              <div className="empty">
                <div className="empty-icon">
                  ✎
                </div>

                <div className="empty-title">
                  Nothing here yet
                </div>

                <div className="empty-text">
                  Create a note and it will
                  appear here.
                </div>
              </div>
            ) : (
              <div className="notes">
                {notes.map((note) => (
                  <article
                    className="note"
                    key={note.id.toString()}
                  >
                    <div className="note-head">
                      <h3 className="note-title">
                        {note.title}
                      </h3>
                    </div>

                    <p className="note-body">
                      {note.body}
                    </p>

                    <div className="note-footer">
                      <span className="note-id">
                        #{(note.id + 1n).toString()}
                      </span>

                      <div className="actions">
                        <button
                          className="action"
                          onClick={() =>
                            startEdit(note)
                          }
                          disabled={loading}
                        >
                          Edit
                        </button>

                        <button
                          className="action delete"
                          onClick={() =>
                            void removeNote(
                              note.id
                            )
                          }
                          disabled={loading}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}

export default App;