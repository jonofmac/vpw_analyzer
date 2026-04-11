"""
Message queue UI: named groups of VPW frames (header + payload) for ordered transmit.
Opened as a Toplevel from the main VPW Analyzer window.
"""
import json
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import tkinter.ttk as ttk

EXPORT_FORMAT_VERSION = 1


class MessageQueueStore:
    """In-memory queue groups shared while the app runs (survives closing the window)."""

    def __init__(self):
        self.groups = []  # [{"name": str, "messages": [{"header","payload","description"}]}]

    def add_group(self, name):
        self.groups.append({"name": name, "messages": []})
        return len(self.groups) - 1

    def append_message(self, group_index, header, payload, description=""):
        if 0 <= group_index < len(self.groups):
            self.groups[group_index]["messages"].append(
                {
                    "header": header.strip(),
                    "payload": payload.strip(),
                    "description": (description or "").strip(),
                }
            )

    @staticmethod
    def _normalize_group(obj):
        if not isinstance(obj, dict):
            return None
        name = obj.get("name")
        if not isinstance(name, str) or not name.strip():
            return None
        raw_msgs = obj.get("messages", [])
        if not isinstance(raw_msgs, list):
            return None
        messages = []
        for m in raw_msgs:
            if not isinstance(m, dict):
                continue
            h = m.get("header", "")
            p = m.get("payload", "")
            d = m.get("description", "")
            if not isinstance(h, str):
                h = str(h)
            if not isinstance(p, str):
                p = str(p)
            if not isinstance(d, str):
                d = str(d)
            messages.append(
                {"header": h.strip(), "payload": p.strip(), "description": d.strip()}
            )
        return {"name": name.strip(), "messages": messages}

    def replace_all_from_import(self, groups):
        """groups: list of normalized {name, messages} dicts."""
        self.groups = groups

    def extend_from_import(self, groups):
        self.groups.extend(groups)


class MessageQueueWindow:
    # Treeview column ids from identify_column() → message dict keys
    _MSG_COL_TO_FIELD = {"#1": "header", "#2": "payload", "#3": "description"}

    def __init__(self, parent, application, store):
        self.app = application
        self.store = store
        self._edit_entry = None
        self._edit_context = None  # (qi, mi, field_key)
        self.win = tk.Toplevel(parent)
        self.win.title("Message queues")
        self.win.geometry("900x520")
        self.win.minsize(640, 360)

        outer = ttk.Frame(self.win, padding=6)
        outer.pack(fill=tk.BOTH, expand=True)

        note = ttk.Label(
            outer,
            text="Note: sending an entire queue back-to-back is currently only supported with OBDX Pro (DVI mode).",
            wraplength=860,
            foreground="#333",
            font=("TkDefaultFont", 9),
        )
        note.pack(anchor=tk.W, fill=tk.X, pady=(0, 6))

        ttk.Label(outer, text="Queue groups").pack(anchor=tk.W)
        paned = ttk.Panedwindow(outer, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        top_f = ttk.Frame(paned)
        bot_f = ttk.Frame(paned)
        paned.add(top_f, weight=1)
        paned.add(bot_f, weight=2)

        q_bar = ttk.Frame(top_f)
        q_bar.pack(fill=tk.X)
        ttk.Button(q_bar, text="New queue", command=self._new_queue).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(q_bar, text="Rename", command=self._rename_queue).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(q_bar, text="Duplicate", command=self._duplicate_queue).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(q_bar, text="Delete queue", command=self._delete_queue).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(q_bar, text="Export…", command=self._export_queues).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(q_bar, text="Import…", command=self._import_queues).pack(side=tk.LEFT)

        self.queue_tree = ttk.Treeview(top_f, columns=("count",), show="tree headings", height=6)
        self.queue_tree.heading("#0", text="Name")
        self.queue_tree.heading("count", text="# Msgs")
        self.queue_tree.column("#0", width=280, stretch=True)
        self.queue_tree.column("count", width=70, stretch=False)
        q_scroll = ttk.Scrollbar(top_f, orient=tk.VERTICAL, command=self.queue_tree.yview)
        self.queue_tree.configure(yscrollcommand=q_scroll.set)
        self.queue_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        q_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.queue_tree.bind("<<TreeviewSelect>>", self._on_queue_select)

        ttk.Label(bot_f, text="Messages in selected queue (reorder with Move up / Move down)").pack(anchor=tk.W)
        m_bar = ttk.Frame(bot_f)
        m_bar.pack(fill=tk.X, pady=(2, 4))
        ttk.Button(m_bar, text="Move up", command=lambda: self._move_message(-1)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(m_bar, text="Move down", command=lambda: self._move_message(1)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(m_bar, text="Remove", command=self._remove_message).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(m_bar, text="Load into transmit", command=self._load_selected_into_transmit).pack(
            side=tk.LEFT, padx=(0, 12)
        )
        ttk.Button(m_bar, text="Send entire queue", command=self._send_entire_queue).pack(side=tk.LEFT)

        self.msg_tree = ttk.Treeview(
            bot_f,
            columns=("header", "payload", "description"),
            show="headings",
            height=12,
        )
        for cid, txt, w in (
            ("header", "Header", 140),
            ("payload", "Payload", 220),
            ("description", "Description", 360),
        ):
            self.msg_tree.heading(cid, text=txt)
            self.msg_tree.column(cid, width=w, stretch=True)
        m_scroll = ttk.Scrollbar(bot_f, orient=tk.VERTICAL, command=self.msg_tree.yview)
        self.msg_tree.configure(yscrollcommand=m_scroll.set)
        self.msg_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        m_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.msg_tree.bind("<Double-1>", self._on_msg_tree_double_click)
        self.msg_tree.bind("<Button-1>", self._on_msg_tree_click_dismiss_edit, add=True)

        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self._refresh_queue_list()
        self._refresh_messages()

    def _cancel_cell_edit(self):
        if self._edit_entry is not None:
            try:
                self._edit_entry.destroy()
            except tk.TclError:
                pass
            self._edit_entry = None
            self._edit_context = None

    def _on_msg_tree_click_dismiss_edit(self, event):
        if self._edit_entry is None:
            return
        try:
            if str(event.widget) == str(self._edit_entry):
                return
        except tk.TclError:
            pass
        self._cancel_cell_edit()

    def _on_msg_tree_double_click(self, event):
        region = self.msg_tree.identify_region(event.x, event.y)
        if region not in ("cell", "tree"):
            return
        row = self.msg_tree.identify_row(event.y)
        if not row:
            return
        self.msg_tree.selection_set(row)
        col = self.msg_tree.identify_column(event.x)
        field = self._MSG_COL_TO_FIELD.get(col)
        if not field and col == "#0":
            field = "header"
        if not field:
            return
        qi = self._selected_queue_index()
        try:
            mi = int(row)
        except (ValueError, TypeError):
            return
        if qi is None or mi < 0 or mi >= len(self.store.groups[qi]["messages"]):
            return
        bbox = self.msg_tree.bbox(row, col)
        if not bbox:
            return
        self._cancel_cell_edit()
        x, y, w, h = bbox
        msg = self.store.groups[qi]["messages"][mi]
        initial = msg.get(field, "")
        ent = tk.Entry(self.msg_tree, relief=tk.SOLID, borderwidth=1, highlightthickness=1)
        ent.insert(0, initial)
        ent.select_range(0, tk.END)
        ent.place(x=x, y=y, width=max(w, 80), height=h)
        ent.focus_set()
        self._edit_entry = ent
        self._edit_context = (qi, mi, field)

        def commit(_event=None):
            self._commit_cell_edit()
            return "break"

        def cancel(_event=None):
            self._cancel_cell_edit()
            return "break"

        ent.bind("<Return>", commit)
        ent.bind("<KP_Enter>", commit)
        ent.bind("<Escape>", cancel)

    def _commit_cell_edit(self):
        if self._edit_entry is None or self._edit_context is None:
            return
        qi, mi, field = self._edit_context
        text = self._edit_entry.get().strip()
        if field in ("header", "payload"):
            text = " ".join(text.split())
        try:
            if 0 <= qi < len(self.store.groups):
                msgs = self.store.groups[qi]["messages"]
                if 0 <= mi < len(msgs):
                    msgs[mi][field] = text
        except (IndexError, KeyError):
            pass
        self._cancel_cell_edit()
        self._refresh_queue_list()
        self.queue_tree.selection_set(str(qi))
        self._refresh_messages()
        self.msg_tree.selection_set(str(mi))
        self.msg_tree.see(str(mi))

    def refresh_preserve_selection(self):
        """Refresh both trees after store changed elsewhere; keep queue + message selection."""
        self._cancel_cell_edit()
        qi = self._selected_queue_index()
        mi = self._selected_message_index()
        self._refresh_queue_list()
        if qi is not None and 0 <= qi < len(self.store.groups):
            self.queue_tree.selection_set(str(qi))
            self.queue_tree.focus(str(qi))
            self.queue_tree.see(str(qi))
            self._refresh_messages()
            if mi is not None and 0 <= mi < len(self.store.groups[qi]["messages"]):
                self.msg_tree.selection_set(str(mi))
                self.msg_tree.focus(str(mi))
                self.msg_tree.see(str(mi))
        else:
            self._refresh_messages()

    def _load_selected_into_transmit(self):
        qi = self._selected_queue_index()
        mi = self._selected_message_index()
        if qi is None or mi is None:
            messagebox.showinfo("Transmit", "Select a message in the list.", parent=self.win)
            return
        m = self.store.groups[qi]["messages"][mi]
        self.app.header_entry.delete(0, tk.END)
        self.app.header_entry.insert(0, m["header"])
        self.app.payload_entry.delete(0, tk.END)
        self.app.payload_entry.insert(0, m["payload"])

    def _export_queues(self):
        path = filedialog.asksaveasfilename(
            parent=self.win,
            title="Export message queues",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialfile="vpw_message_queues.json",
        )
        if not path:
            return
        doc = {
            "format": "vpw_analyzer_message_queues",
            "version": EXPORT_FORMAT_VERSION,
            "queues": self.store.groups,
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
                f.write("\n")
        except OSError as e:
            messagebox.showerror("Export", f"Could not write file:\n{e}", parent=self.win)

    def _import_queues(self):
        path = filedialog.askopenfilename(
            parent=self.win,
            title="Import message queues",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            messagebox.showerror("Import", f"Could not read JSON:\n{e}", parent=self.win)
            return
        groups_in = None
        if isinstance(doc, list):
            groups_in = doc
        elif isinstance(doc, dict):
            if doc.get("format") == "vpw_analyzer_message_queues" and "queues" in doc:
                groups_in = doc["queues"]
            elif "queues" in doc:
                groups_in = doc["queues"]
        if not isinstance(groups_in, list):
            messagebox.showerror(
                "Import",
                "Unrecognized file format. Expected a JSON object with a \"queues\" array.",
                parent=self.win,
            )
            return
        normalized = []
        for item in groups_in:
            g = MessageQueueStore._normalize_group(item)
            if g:
                normalized.append(g)
        if not normalized:
            messagebox.showwarning("Import", "No valid queues found in file.", parent=self.win)
            return
        append = messagebox.askyesno(
            "Import",
            "Append imported queues after your current queues?\n\n"
            "Yes = append\nNo = replace all current queues",
            parent=self.win,
        )
        self._cancel_cell_edit()
        if append:
            self.store.extend_from_import(normalized)
        else:
            if self.store.groups and not messagebox.askyesno(
                "Replace queues",
                f"This will remove all {len(self.store.groups)} current queue(s) and replace them "
                f"with {len(normalized)} from the file. Continue?",
                parent=self.win,
            ):
                return
            self.store.replace_all_from_import(normalized)
        self._refresh_queue_list()
        new_qi = len(self.store.groups) - len(normalized) if append else 0
        new_qi = max(0, min(new_qi, len(self.store.groups) - 1))
        self.queue_tree.selection_set(str(new_qi))
        self.queue_tree.see(str(new_qi))
        self._refresh_messages()

    def _on_close(self):
        if getattr(self.app, "_message_queue_toplevel", None) is self:
            self.app._message_queue_toplevel = None
        self.win.destroy()

    def _selected_queue_index(self):
        sel = self.queue_tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except (ValueError, TypeError):
            return None

    def _selected_message_index(self):
        sel = self.msg_tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except (ValueError, TypeError):
            return None

    def _refresh_queue_list(self):
        self._cancel_cell_edit()
        for i in self.queue_tree.get_children():
            self.queue_tree.delete(i)
        for i, g in enumerate(self.store.groups):
            self.queue_tree.insert("", tk.END, iid=str(i), text=g["name"], values=(str(len(g["messages"])),))

    def _refresh_messages(self):
        self._cancel_cell_edit()
        for i in self.msg_tree.get_children():
            self.msg_tree.delete(i)
        qi = self._selected_queue_index()
        if qi is None or qi >= len(self.store.groups):
            return
        for j, m in enumerate(self.store.groups[qi]["messages"]):
            self.msg_tree.insert(
                "",
                tk.END,
                iid=str(j),
                values=(m["header"], m["payload"], m.get("description", "")),
            )

    def _on_queue_select(self, event=None):
        self._cancel_cell_edit()
        self._refresh_messages()

    def _new_queue(self):
        name = simpledialog.askstring("New queue", "Queue name:", parent=self.win)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        self.store.add_group(name)
        self._refresh_queue_list()
        last = str(len(self.store.groups) - 1)
        self.queue_tree.selection_set(last)
        self.queue_tree.focus(last)
        self._refresh_messages()

    def _duplicate_queue(self):
        qi = self._selected_queue_index()
        if qi is None:
            messagebox.showinfo("Duplicate", "Select a queue first.", parent=self.win)
            return
        src = self.store.groups[qi]
        suggested = f"{src['name']} copy"
        name = simpledialog.askstring(
            "Duplicate queue",
            "Name for the new queue:",
            parent=self.win,
            initialvalue=suggested,
        )
        if not name:
            return
        name = name.strip()
        if not name:
            return
        new_msgs = [
            {
                "header": m["header"],
                "payload": m["payload"],
                "description": m.get("description", ""),
            }
            for m in src["messages"]
        ]
        self.store.groups.append({"name": name, "messages": new_msgs})
        self._refresh_queue_list()
        new_i = str(len(self.store.groups) - 1)
        self.queue_tree.selection_set(new_i)
        self.queue_tree.focus(new_i)
        self.queue_tree.see(new_i)
        self._refresh_messages()

    def _rename_queue(self):
        qi = self._selected_queue_index()
        if qi is None:
            messagebox.showinfo("Rename", "Select a queue first.", parent=self.win)
            return
        old = self.store.groups[qi]["name"]
        name = simpledialog.askstring("Rename queue", "Queue name:", parent=self.win, initialvalue=old)
        if not name:
            return
        name = name.strip()
        if name:
            self.store.groups[qi]["name"] = name
            self._refresh_queue_list()
            self.queue_tree.selection_set(str(qi))
            self.queue_tree.focus(str(qi))
            self._refresh_messages()

    def _delete_queue(self):
        qi = self._selected_queue_index()
        if qi is None:
            messagebox.showinfo("Delete", "Select a queue first.", parent=self.win)
            return
        if not messagebox.askyesno(
            "Delete queue",
            f"Delete queue \"{self.store.groups[qi]['name']}\" and all its messages?",
            parent=self.win,
        ):
            return
        del self.store.groups[qi]
        self._refresh_queue_list()
        if self.store.groups:
            nqi = min(qi, len(self.store.groups) - 1)
            self.queue_tree.selection_set(str(nqi))
            self.queue_tree.focus(str(nqi))
        self._refresh_messages()

    def _move_message(self, delta):
        qi = self._selected_queue_index()
        mi = self._selected_message_index()
        if qi is None or mi is None:
            messagebox.showinfo("Reorder", "Select a message in the list.", parent=self.win)
            return
        msgs = self.store.groups[qi]["messages"]
        ni = mi + delta
        if ni < 0 or ni >= len(msgs):
            return
        msgs[mi], msgs[ni] = msgs[ni], msgs[mi]
        self._refresh_messages()
        self.msg_tree.selection_set(str(ni))
        self.msg_tree.focus(str(ni))

    def _remove_message(self):
        qi = self._selected_queue_index()
        mi = self._selected_message_index()
        if qi is None or mi is None:
            messagebox.showinfo("Remove", "Select a message to remove.", parent=self.win)
            return
        del self.store.groups[qi]["messages"][mi]
        self._refresh_queue_list()
        if 0 <= qi < len(self.store.groups):
            self.queue_tree.selection_set(str(qi))
            self.queue_tree.focus(str(qi))
        self._refresh_messages()
        if self.store.groups[qi]["messages"]:
            self.msg_tree.selection_set(str(min(mi, len(self.store.groups[qi]["messages"]) - 1)))

    def _send_entire_queue(self):
        qi = self._selected_queue_index()
        if qi is None:
            messagebox.showinfo("Send", "Select a queue first.", parent=self.win)
            return
        if not self.app.tool_manager.is_connected:
            messagebox.showwarning("Not connected", "Open a serial device with Read/Open first.", parent=self.win)
            return
        if not self.app.tool_manager.obd or not self.app.tool_manager.obd.serial:
            messagebox.showinfo("Transmit", "Transmit is only available on a live serial connection.", parent=self.win)
            return
        msgs = self.store.groups[qi]["messages"]
        if not msgs:
            messagebox.showinfo("Send", "This queue has no messages.", parent=self.win)
            return
        for idx, m in enumerate(msgs):
            ok = self.app.tool_manager.send_message(m["header"], m["payload"])
            if ok:
                self.app._maybe_record_transmit_echo(m["header"], m["payload"])
            else:
                messagebox.showerror(
                    "Transmit failed",
                    f"Stopped at message {idx + 1} of {len(msgs)}.\nCheck hex fields and connection.",
                    parent=self.win,
                )
                return
            time.sleep(0.03)
        cur = self.app.statusBarOBDString.get()
        if cur.startswith("OBD: Connected"):
            base = cur.split(" — ")[0]
            self.app.statusBarOBDString.set(base + " — Last transmit: OK (queue)")

def description_from_tree_values(values, is_summary):
    """Human-readable note from Summary or History row values."""
    if not values:
        return ""
    if is_summary and len(values) > 10:
        return str(values[10])
    if not is_summary and len(values) > 9:
        return str(values[9])
    return ""


def open_or_raise_message_queue_window(application):
    """Create the message queue Toplevel or bring it to front."""
    win = getattr(application, "_message_queue_toplevel", None)
    if win is not None:
        try:
            if win.win.winfo_exists():
                win.win.lift()
                win.win.focus_force()
                win.refresh_preserve_selection()
                return win
        except tk.TclError:
            pass
    application._message_queue_toplevel = MessageQueueWindow(
        application.root, application, application.message_queue_store
    )
    return application._message_queue_toplevel


def destroy_message_queue_window_if_any(application):
    win = getattr(application, "_message_queue_toplevel", None)
    if win is None:
        return
    try:
        if win.win.winfo_exists():
            win.win.destroy()
    except tk.TclError:
        pass
    application._message_queue_toplevel = None
