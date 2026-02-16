import express from 'express';
import cors from 'cors';
import { all, get, initDb, run } from './db.js';

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

initDb();

function normalizeNoteInput(body = {}) {
  return {
    title: body.title ?? '',
    content: body.content ?? '',
    color: body.color ?? '#ffffff',
    pinned: body.pinned ? 1 : 0,
    archived: body.archived ? 1 : 0,
    tags: JSON.stringify(Array.isArray(body.tags) ? body.tags : []),
    checklist: JSON.stringify(Array.isArray(body.checklist) ? body.checklist : [])
  };
}

function toNote(row) {
  return {
    ...row,
    pinned: !!row.pinned,
    archived: !!row.archived,
    tags: JSON.parse(row.tags || '[]'),
    checklist: JSON.parse(row.checklist || '[]')
  };
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/notes', async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    const archiveMode = req.query.archived;

    let rows = await all('SELECT * FROM notes ORDER BY pinned DESC, updated_at DESC');

    rows = rows.map(toNote);

    if (archiveMode === 'true') rows = rows.filter((n) => n.archived);
    if (archiveMode === 'false') rows = rows.filter((n) => !n.archived);

    if (q) {
      rows = rows.filter((n) => {
        const checklistText = n.checklist.map((i) => i.text).join(' ');
        const haystack = `${n.title} ${n.content} ${n.tags.join(' ')} ${checklistText}`.toLowerCase();
        return haystack.includes(q);
      });
    }

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/notes/:id', async (req, res) => {
  try {
    const row = await get('SELECT * FROM notes WHERE id = ?', [req.params.id]);
    if (!row) return res.status(404).json({ error: 'Note not found' });
    return res.json(toNote(row));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/notes', async (req, res) => {
  try {
    const note = normalizeNoteInput(req.body);
    const now = new Date().toISOString();

    const result = await run(
      `INSERT INTO notes (title, content, color, pinned, archived, tags, checklist, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [note.title, note.content, note.color, note.pinned, note.archived, note.tags, note.checklist, now, now]
    );

    const row = await get('SELECT * FROM notes WHERE id = ?', [result.id]);
    res.status(201).json(toNote(row));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/notes/:id', async (req, res) => {
  try {
    const existing = await get('SELECT * FROM notes WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Note not found' });

    const base = toNote(existing);
    const mergedInput = normalizeNoteInput({ ...base, ...req.body });
    const now = new Date().toISOString();

    await run(
      `UPDATE notes
       SET title = ?, content = ?, color = ?, pinned = ?, archived = ?, tags = ?, checklist = ?, updated_at = ?
       WHERE id = ?`,
      [
        mergedInput.title,
        mergedInput.content,
        mergedInput.color,
        mergedInput.pinned,
        mergedInput.archived,
        mergedInput.tags,
        mergedInput.checklist,
        now,
        req.params.id
      ]
    );

    const row = await get('SELECT * FROM notes WHERE id = ?', [req.params.id]);
    return res.json(toNote(row));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/notes/:id', async (req, res) => {
  try {
    const result = await run('DELETE FROM notes WHERE id = ?', [req.params.id]);
    if (!result.changes) return res.status(404).json({ error: 'Note not found' });
    return res.status(204).send();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});
