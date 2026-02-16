import { useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';
const COLORS = ['#fff8b8', '#ffd6a5', '#fdffb6', '#caffbf', '#9bf6ff', '#bdb2ff', '#ffc6ff', '#ffffff'];

const emptyDraft = {
  title: '',
  content: '',
  color: '#ffffff',
  pinned: false,
  archived: false,
  tagsInput: '',
  checklistInput: '',
  checklist: []
};

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });

  if (!res.ok) {
    if (res.status === 204) return null;
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

  async function loadNotes() {
    setLoading(true);
    setError('');
    try {
      const data = await api(`/notes?archived=${showArchived}&q=${encodeURIComponent(search)}`);
      setNotes(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadNotes();
  }, [search, showArchived]);

  const pinnedNotes = useMemo(() => notes.filter((n) => n.pinned), [notes]);
  const otherNotes = useMemo(() => notes.filter((n) => !n.pinned), [notes]);

  const checklistItems = draft.checklistInput
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean)
    .map((text) => ({ text, done: false }));

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

    await api('/notes', { method: 'POST', body: JSON.stringify(payload) });
    setDraft(emptyDraft);
    loadNotes();
  }

  async function togglePin(note) {
    await api(`/notes/${note.id}`, { method: 'PUT', body: JSON.stringify({ pinned: !note.pinned }) });
    loadNotes();
  }

  async function toggleArchive(note) {
    await api(`/notes/${note.id}`, { method: 'PUT', body: JSON.stringify({ archived: !note.archived }) });
    loadNotes();
  }

  async function removeNote(id) {
    await api(`/notes/${id}`, { method: 'DELETE' });
    loadNotes();
  }

  async function toggleChecklistItem(note, idx) {
    const checklist = note.checklist.map((item, i) => (i === idx ? { ...item, done: !item.done } : item));
    await api(`/notes/${note.id}`, { method: 'PUT', body: JSON.stringify({ checklist }) });
    loadNotes();
  }

  return (
    <div className="app">
      <header>
        <h1>Keep Clone MVP</h1>
        <div className="toolbar">
          <input
            placeholder="Search title, content, tags..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button onClick={() => setShowArchived((s) => !s)}>
            {showArchived ? 'Show Active' : 'Show Archived'}
          </button>
        </div>
      </header>

      <form className="composer" onSubmit={createNote}>
        <input
          placeholder="Title"
          value={draft.title}
          onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))}
        />
        <textarea
          placeholder="Take a note..."
          value={draft.content}
          onChange={(e) => setDraft((d) => ({ ...d, content: e.target.value }))}
        />
        <input
          placeholder="Tags (comma separated)"
          value={draft.tagsInput}
          onChange={(e) => setDraft((d) => ({ ...d, tagsInput: e.target.value }))}
        />
        <input
          placeholder="Checklist items (comma separated)"
          value={draft.checklistInput}
          onChange={(e) => setDraft((d) => ({ ...d, checklistInput: e.target.value }))}
        />
        <div className="row">
          <label>
            Color
            <select value={draft.color} onChange={(e) => setDraft((d) => ({ ...d, color: e.target.value }))}>
              {COLORS.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </label>
          <label><input type="checkbox" checked={draft.pinned} onChange={(e) => setDraft((d) => ({ ...d, pinned: e.target.checked }))} /> Pin</label>
          <label><input type="checkbox" checked={draft.archived} onChange={(e) => setDraft((d) => ({ ...d, archived: e.target.checked }))} /> Archive</label>
          <button type="submit">Add Note</button>
        </div>
      </form>

      {error && <p className="error">{error}</p>}
      {loading ? <p>Loading...</p> : (
        <>
          {pinnedNotes.length > 0 && (
            <section>
              <h2>Pinned</h2>
              <NoteGrid notes={pinnedNotes} onPin={togglePin} onArchive={toggleArchive} onDelete={removeNote} onToggleChecklist={toggleChecklistItem} />
            </section>
          )}
          <section>
            <h2>{showArchived ? 'Archived' : 'Notes'}</h2>
            <NoteGrid notes={otherNotes} onPin={togglePin} onArchive={toggleArchive} onDelete={removeNote} onToggleChecklist={toggleChecklistItem} />
          </section>
        </>
      )}
    </div>
  );
}

function NoteGrid({ notes, onPin, onArchive, onDelete, onToggleChecklist }) {
  if (!notes.length) return <p>No notes yet.</p>;

  return (
    <div className="grid">
      {notes.map((note) => (
        <article key={note.id} className="note" style={{ backgroundColor: note.color }}>
          <h3>{note.title || 'Untitled'}</h3>
          <p>{note.content}</p>
          {note.tags?.length > 0 && (
            <div className="tags">
              {note.tags.map((tag) => <span key={`${note.id}-${tag}`}>#{tag}</span>)}
            </div>
          )}
          {note.checklist?.length > 0 && (
            <ul>
              {note.checklist.map((item, idx) => (
                <li key={`${note.id}-${idx}`}>
                  <label>
                    <input type="checkbox" checked={item.done} onChange={() => onToggleChecklist(note, idx)} />
                    <span className={item.done ? 'done' : ''}>{item.text}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          <div className="actions">
            <button onClick={() => onPin(note)}>{note.pinned ? 'Unpin' : 'Pin'}</button>
            <button onClick={() => onArchive(note)}>{note.archived ? 'Unarchive' : 'Archive'}</button>
            <button onClick={() => onDelete(note.id)}>Delete</button>
          </div>
        </article>
      ))}
    </div>
  );
}
