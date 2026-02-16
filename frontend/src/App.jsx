import { useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';
const COLORS = ['#fff8b8', '#ffd6a5', '#fdffb6', '#caffbf', '#9bf6ff', '#bdb2ff', '#ffc6ff', '#ffffff'];

const emptyDraft = { title: '', content: '', color: '#ffffff', pinned: false, archived: false, tagsInput: '', checklistInput: '' };

async function api(path, options = {}, accessToken, refreshToken, onTokens) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' });

  if (res.status === 401 && refreshToken && path !== '/auth/refresh') {
    const refreshed = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    if (refreshed.ok) {
      const tokens = await refreshed.json();
      onTokens(tokens);
      headers.Authorization = `Bearer ${tokens.accessToken}`;
      res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: 'include' });
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || 'Request failed');
  }
  if (res.status === 204) return null;
  return res.json();
}

export default function App() {
  const [notes, setNotes] = useState([]);
  const [draft, setDraft] = useState(emptyDraft);
  const [search, setSearch] = useState('');
  const [showArchived, setShowArchived] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [user, setUser] = useState(null);
  const [mode, setMode] = useState('login');
  const [authForm, setAuthForm] = useState({ email: '', password: '' });
  const [tokens, setTokens] = useState(() => ({
    accessToken: localStorage.getItem('accessToken') || '',
    refreshToken: localStorage.getItem('refreshToken') || ''
  }));
  const [importPayload, setImportPayload] = useState('');

  function saveTokens(data) {
    const next = { accessToken: data.accessToken || '', refreshToken: data.refreshToken || '' };
    setTokens(next);
    localStorage.setItem('accessToken', next.accessToken);
    localStorage.setItem('refreshToken', next.refreshToken);
    if (data.user) setUser(data.user);
  }

  async function auth(path) {
    const data = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(authForm)
    }).then(async (r) => {
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'Authentication failed');
      return r.json();
    });
    saveTokens(data);
  }

  async function loadNotes() {
    if (!tokens.accessToken) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const data = await api(`/notes?archived=${showArchived}&q=${encodeURIComponent(search)}`, {}, tokens.accessToken, tokens.refreshToken, saveTokens);
      setNotes(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!tokens.accessToken) return;
    api('/auth/me', {}, tokens.accessToken, tokens.refreshToken, saveTokens).then((r) => setUser(r.user)).catch(() => setUser(null));
  }, [tokens.accessToken]);

  useEffect(() => {
    loadNotes();
  }, [search, showArchived, tokens.accessToken]);

  const pinnedNotes = useMemo(() => notes.filter((n) => n.pinned), [notes]);
  const otherNotes = useMemo(() => notes.filter((n) => !n.pinned), [notes]);

  const checklistItems = draft.checklistInput.split(',').map((t) => t.trim()).filter(Boolean).map((text) => ({ text, done: false }));

  async function createNote(e) {
    e.preventDefault();
    const payload = {
      title: draft.title,
      content: draft.content,
      color: draft.color,
      pinned: draft.pinned,
      archived: draft.archived,
      tags: draft.tagsInput.split(',').map((t) => t.trim()).filter(Boolean),
      checklist: checklistItems
    };
    await api('/notes', { method: 'POST', body: JSON.stringify(payload) }, tokens.accessToken, tokens.refreshToken, saveTokens);
    setDraft(emptyDraft);
    loadNotes();
  }

  async function mutate(path, method, body) {
    await api(path, { method, body: body ? JSON.stringify(body) : undefined }, tokens.accessToken, tokens.refreshToken, saveTokens);
    loadNotes();
  }

  async function logout() {
    await mutate('/auth/logout', 'POST', { refreshToken: tokens.refreshToken }).catch(() => undefined);
    setTokens({ accessToken: '', refreshToken: '' });
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    setNotes([]);
  }

  async function doExport(type) {
    const data = await api(`/export/${type}`, {}, tokens.accessToken, tokens.refreshToken, saveTokens);
    setImportPayload(JSON.stringify(data, null, 2));
  }

  async function doImport(type) {
    const payload = JSON.parse(importPayload || '{}');
    await api(`/import/${type}`, { method: 'POST', body: JSON.stringify(payload) }, tokens.accessToken, tokens.refreshToken, saveTokens);
    await loadNotes();
  }

  if (!tokens.accessToken || !user) {
    return (
      <div className="app">
        <h1>KeepLite V2</h1>
        <p>Secure sign-in required.</p>
        <div className="composer">
          <input placeholder="Email" value={authForm.email} onChange={(e) => setAuthForm((v) => ({ ...v, email: e.target.value }))} />
          <input type="password" placeholder="Password" value={authForm.password} onChange={(e) => setAuthForm((v) => ({ ...v, password: e.target.value }))} />
          <div className="row">
            <button onClick={() => auth(mode === 'login' ? '/auth/login' : '/auth/register')}>{mode === 'login' ? 'Login' : 'Register'}</button>
            <button onClick={() => setMode((m) => (m === 'login' ? 'register' : 'login'))}>{mode === 'login' ? 'Need account?' : 'Have account?'}</button>
          </div>
          {error && <p className="error">{error}</p>}
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <header>
        <h1>KeepLite V2</h1>
        <div className="toolbar">
          <input placeholder="Search" value={search} onChange={(e) => setSearch(e.target.value)} />
          <button onClick={() => setShowArchived((s) => !s)}>{showArchived ? 'Show Active' : 'Show Archived'}</button>
          <span>{user.email} ({user.role})</span>
          <button onClick={logout}>Logout</button>
        </div>
      </header>

      <form className="composer" onSubmit={createNote}>
        <input placeholder="Title" value={draft.title} onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))} />
        <textarea placeholder="Take a note..." value={draft.content} onChange={(e) => setDraft((d) => ({ ...d, content: e.target.value }))} />
        <input placeholder="Tags" value={draft.tagsInput} onChange={(e) => setDraft((d) => ({ ...d, tagsInput: e.target.value }))} />
        <input placeholder="Checklist items" value={draft.checklistInput} onChange={(e) => setDraft((d) => ({ ...d, checklistInput: e.target.value }))} />
        <div className="row">
          <select value={draft.color} onChange={(e) => setDraft((d) => ({ ...d, color: e.target.value }))}>{COLORS.map((c) => <option key={c} value={c}>{c}</option>)}</select>
          <label><input type="checkbox" checked={draft.pinned} onChange={(e) => setDraft((d) => ({ ...d, pinned: e.target.checked }))} /> Pin</label>
          <label><input type="checkbox" checked={draft.archived} onChange={(e) => setDraft((d) => ({ ...d, archived: e.target.checked }))} /> Archive</label>
          <button type="submit">Add</button>
        </div>
      </form>

      <section className="composer">
        <h3>Import / Export</h3>
        <div className="row">
          <button onClick={() => doExport('json')}>Export JSON</button>
          <button onClick={() => doExport('markdown')}>Export Markdown Folder</button>
          <button onClick={() => doImport('json')}>Import JSON</button>
          <button onClick={() => doImport('markdown')}>Import Markdown</button>
          <button onClick={() => doImport('keep')}>Import Keep JSON</button>
        </div>
        <textarea value={importPayload} onChange={(e) => setImportPayload(e.target.value)} placeholder="Paste import payload or view export..." />
      </section>

      {error && <p className="error">{error}</p>}
      {loading ? <p>Loading...</p> : (
        <>
          {pinnedNotes.length > 0 && <section><h2>Pinned</h2><NoteGrid notes={pinnedNotes} mutate={mutate} /></section>}
          <section><h2>{showArchived ? 'Archived' : 'Notes'}</h2><NoteGrid notes={otherNotes} mutate={mutate} /></section>
        </>
      )}
    </div>
  );
}

function NoteGrid({ notes, mutate }) {
  if (!notes.length) return <p>No notes yet.</p>;
  return <div className="grid">{notes.map((note) => (
    <article key={note.id} className="note" style={{ backgroundColor: note.color }}>
      <h3>{note.title || 'Untitled'}</h3>
      <p>{note.content}</p>
      {note.tags?.length > 0 && <div className="tags">{note.tags.map((t) => <span key={`${note.id}-${t}`}>#{t}</span>)}</div>}
      {note.checklist?.length > 0 && <ul>{note.checklist.map((item, idx) => (
        <li key={`${note.id}-${idx}`}>
          <label>
            <input type="checkbox" checked={item.done} onChange={() => mutate(`/notes/${note.id}`, 'PUT', { checklist: note.checklist.map((it, i) => i === idx ? { ...it, done: !it.done } : it) })} />
            <span className={item.done ? 'done' : ''}>{item.text}</span>
          </label>
        </li>
      ))}</ul>}
      <div className="actions">
        <button onClick={() => mutate(`/notes/${note.id}`, 'PUT', { pinned: !note.pinned })}>{note.pinned ? 'Unpin' : 'Pin'}</button>
        <button onClick={() => mutate(`/notes/${note.id}`, 'PUT', { archived: !note.archived })}>{note.archived ? 'Unarchive' : 'Archive'}</button>
        <button onClick={() => mutate(`/notes/${note.id}`, 'DELETE')}>Delete</button>
      </div>
    </article>
  ))}</div>;
}
