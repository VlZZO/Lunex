import os
import re
import sys
import json
import shutil
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from dataclasses import dataclass, field
from pathlib import Path

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

# NOT TOUCH >:(
#---------------------------------------------------------

BaseDir = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
autoSearch = ["Deflection.hks"]

t_TagColors = {
    "RED": "#ff5d6c", "GREEN": "#39d98a", "BLUE": "#5b9dff", "YELLOW": "#ffd166",
    "ORANGE": "#ff9f43", "PURPLE": "#b389ff", "CYAN": "#3ee0d6", "PINK": "#ff7ad9",
    "GRAY": "#8a93a6", "WHITE": "#eef0f4", "BLACK": "#111111",
}

#---------------------------------------------------------


def titleFormat(text):
    text = re.sub(r"^v_", "", text).replace("_", " ")
    return " ".join(w[:1].upper() + w[1:].lower() for w in text.split(" "))


def splitSideFormat(text, separator):
    parts, current, quote = [], "", None
    for char in text:
        if quote:
            current += char
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
            current += char
        elif char == separator:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    return parts


def parseSelect(text):
    options = {}
    for part in splitSideFormat(text or "", ","):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            options[key.strip()] = value.strip()
        elif part:
            options[part] = part
    return options


def isBool(text):
    return text.lower() in ("true", "false")


def sortCAT(categories):
    return sorted(categories, key=lambda c: (c == "System", c != "General", c.lower()))


def addMeta(store, key, value):
    upper = key.upper()
    if key in store and upper in ("HINT", "TAG"):
        store[key] += ("\n" if upper == "HINT" else ",") + value
    else:
        store[key] = value


def hintLines(label, hint):
    return [f"-- [UI] {label}: {line}" for line in hint.split("\n")] if hint else []


def norm(path):
    return os.path.normcase(os.path.abspath(path))


def shortPath(path):
    try:
        text = os.path.relpath(os.path.dirname(path), BaseDir)
    except ValueError:
        text = os.path.dirname(path)
    return text if len(text) <= 32 else "..." + text[-29:]


def recentFiles():
    try:
        with open(BaseDir / "lunexRes" / "lunex_recent.json", "r", encoding="utf-8") as file:
            data = json.load(file)
        return [p for p in data if isinstance(p, str) and os.path.isfile(p)]
    except Exception:
        return []


def updateTempFiles(path, add=True):
    path = os.path.abspath(path)
    recents = [p for p in recentFiles() if norm(p) != norm(path)]
    if add:
        recents.insert(0, path)
    try:
        (BaseDir / "lunexRes").mkdir(exist_ok=True)
        with open(BaseDir / "lunexRes" / "lunex_recent.json", "w", encoding="utf-8") as file:
            json.dump(recents[:20], file, indent=2)
    except Exception:
        pass


def findFiles():
    wanted = {name.lower() for name in autoSearch}
    found = {}
    for dirpath, dirnames, filenames in os.walk(BaseDir):
        dirnames[:] = [d for d in dirnames if d.lower() not in {"node_modules", ".git", ".svn", "__pycache__", "bin", "obj", "cache", ".idea", ".vscode", "res"}]
        for filename in filenames:
            if filename.lower() in wanted:
                path = os.path.join(dirpath, filename)
                found[norm(path)] = path
    return sorted(found.values(), key=str.lower)


def readTXTFile(path):
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        for encoding in ("utf-8-sig", "cp1252", "latin-1"):
            try:
                raw.decode(encoding)
                break
            except UnicodeDecodeError:
                pass
        if encoding == "utf-8-sig" and not raw.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8"
    text = raw.decode(encoding)
    return text.replace("\r\n", "\n"), encoding, "\r\n" if "\r\n" in text else "\n"


def loadLogo(size):
    path = BaseDir / "lunexRes" / "logo.png"
    if not path.is_file():
        return None
    try:
        if HAS_PIL:
            image = Image.open(path).convert("RGBA")
            image.thumbnail((size, size), Image.LANCZOS)
            return ImageTk.PhotoImage(image)
        image = tk.PhotoImage(file=str(path))
        return image.subsample(max(1, round(image.width() / size)))
    except Exception:
        return None


# Lua Format
UIFormat = re.compile(r"^--\s*\[UI\]\s*(\w+)\s*:\s*(.+)$")
TableFieldFormat = re.compile(r"^--\s*\[UI\]\s*TABLEFIELD_(\w+)\s*:\s*(.+)$", re.I)
SectionFormat = re.compile(r"^----+\s*(.+?)\s*----+$")
StartReadFormat = re.compile(r"^--//\s*READ VARIABLES\s*$", re.I)
EndReadFormat = re.compile(r"^--//\s*END READ VARIABLES\s*$", re.I)
CategoryFormat = re.compile(r"^--\s*\[UI\]\s*CATEGORY\s*:\s*(.+)$", re.I)
VariableFormat = re.compile(r"^(local\s+)?([A-Za-z_]\w*)\s*=\s*(?!=)(.+)$")
ReadBlockFormat = re.compile(r"(--//[ \t]*READ VARIABLES[^\n]*\n)(.*?)(^[ \t]*--//[ \t]*END READ VARIABLES)", re.I | re.S | re.M)
StringFormat = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")
KeywordFormat = re.compile(r"\b(function|if|for|while|repeat|do|end|until)\b")


def blackListDPChange(line):
    code = StringFormat.sub('""', line).split("--", 1)[0]
    change, loop_pending = 0, False
    for word in KeywordFormat.findall(code):
        if word in ("function", "if", "repeat"):
            change += 1
        elif word in ("for", "while"):
            change += 1
            loop_pending = True
        elif word == "do":
            if loop_pending:
                loop_pending = False
            else:
                change += 1
        else:
            change -= 1
    return change


@dataclass
class Variable:
    name: str
    type: str
    value: object
    section: str = "General"
    ui_name: str = ""
    hint: str = ""
    tags: list = field(default_factory=list)
    tag_colors: dict = field(default_factory=dict)
    selector: dict = field(default_factory=dict)
    table_fields: dict = field(default_factory=dict)
    is_local: bool = True


def parseTable(block_lines):
    fields, fields_meta, pending = {}, {}, {}

    def addField(name, text):
        nonlocal pending
        fields[name] = text.strip()
        if pending:
            fields_meta[name] = pending
            pending = {}

    first = block_lines[0]
    inline = first[first.find("{") + 1:]
    if "}" in inline:
        inline = inline[:inline.rfind("}")]
    if "=" in inline and "--" not in inline:
        for chunk in splitSideFormat(inline, ","):
            match = re.match(r"^\s*(\w+)\s*=\s*(.+?)\s*$", chunk)
            if match:
                addField(match.group(1), match.group(2))

    for raw in block_lines[1:]:
        line = raw.strip()
        if not line:
            continue
        meta = TableFieldFormat.match(line)
        if meta:
            key = meta.group(1).lower()
            if key in ("name", "hint", "selector"):
                addMeta(pending, key, meta.group(2).strip())
            continue
        if line.startswith("--") or line in ("{", "}"):
            continue
        if line.endswith("}") and "=" in line:
            line = line[:-1].rstrip().rstrip(",")
        match = re.match(r"^(\w+)\s*=\s*(.+)$", line)
        if match:
            addField(match.group(1), match.group(2).split("--")[0].strip().rstrip(","))
    return fields, fields_meta


def parseLua(content):
    lines = content.split("\n")
    start = end = -1
    for i, raw in enumerate(lines):
        line = raw.strip()
        if start == -1 and StartReadFormat.match(line):
            start = i
        elif start != -1 and EndReadFormat.match(line):
            end = i
            break
    block = lines[start + 1:end] if start != -1 and end != -1 else lines

    variables, order, categories = {}, [], []

    def addCAT(name):
        if name and name not in categories and name != "System":
            categories.append(name)

    for raw in block:
        match = CategoryFormat.match(raw.strip())
        if match:
            addCAT(match.group(1).strip())

    meta, section, depth = {}, "General", 0
    it = iter(block)
    for raw in it:
        line = raw.strip()
        if StartReadFormat.match(line) or EndReadFormat.match(line):
            continue

        depth_before = depth
        depth = max(0, depth + blackListDPChange(line))

        match = SectionFormat.match(line)
        if match and re.search(r"\w", match.group(1)):
            section = match.group(1).strip()
            addCAT(section)
            continue

        match = UIFormat.match(line)
        if match and depth_before == 0:
            key, value = match.group(1).upper(), match.group(2).strip()
            addMeta(meta, key, value)
            if key == "CATEGORY":
                addCAT(value)
            continue

        match = VariableFormat.match(line)
        if not match or line.startswith("--") or depth_before != 0:
            continue

        name = match.group(2)
        value_text = match.group(3).split("--")[0].strip()
        if "function" in value_text or "()" in value_text:
            meta = {}
            continue

        table_fields = {}
        if value_text.startswith("{"):
            braces = raw.count("{") - raw.count("}")
            tbl = [raw]
            while braces > 0:
                nxt = next(it, None)
                if nxt is None:
                    break
                tbl.append(nxt)
                braces += nxt.count("{") - nxt.count("}")
            kind = "table"
            value, table_fields = parseTable(tbl)
        elif meta.get("SELECTOR"):
            kind, value = "selector", value_text
        else:
            kind, value = ("boolean" if isBool(value_text) else "text"), value_text

        tags = [t.strip() for t in meta.get("TAG", "").split(",") if t.strip()]
        tag_colors = {tags[0].upper(): meta["TAG_COLOR"].strip().upper()} if tags and meta.get("TAG_COLOR") else {}
        category = meta.get("CATEGORY") or section
        addCAT(category)

        if name not in variables:
            variables[name] = Variable(name=name, type=kind, value=value, section=category, ui_name=meta.get("NAME") or titleFormat(name), hint=meta.get("HINT", ""), tags=tags, 
                tag_colors=tag_colors, selector=parseSelect(meta["SELECTOR"]) if kind == "selector" else {}, table_fields=table_fields, is_local=bool(match.group(1)),)
            order.append(name)
        meta = {}

    if order and "General" not in categories:
        categories.append("General")
    return variables, order, categories


def buildVarTXT(file):
    lines, last_section = [], None
    for var in file.ordered():
        if var.section != last_section:
            if lines:
                lines.append("")
            lines.append(f"---- {var.section} ----")
            last_section = var.section
        lines.append("")

        if var.ui_name and var.ui_name != titleFormat(var.name):
            lines.append(f"-- [UI] NAME: {var.ui_name}")
        lines += hintLines("HINT", var.hint)
        if var.tags:
            lines.append(f"-- [UI] TAG: {', '.join(var.tags)}")
            color = var.tag_colors.get(var.tags[0].upper())
            if color:
                lines.append(f"-- [UI] TAG_COLOR: {color}")
        if var.section != "General" and var.section != "System":
            lines.append(f"-- [UI] CATEGORY: {var.section}")
        if var.type == "selector" and var.selector:
            parts = [k if k == v else f"{k} = {v}" for k, v in var.selector.items()]
            lines.append(f"-- [UI] SELECTOR: {', '.join(parts)}")

        prefix = "local " if var.is_local else ""
        if var.type == "table":
            lines.append(f"{prefix}{var.name} = {{")
            for key, value in var.value.items():
                meta = var.table_fields.get(key, {})
                if meta.get("name"):
                    lines.append(f"-- [UI] TABLEFIELD_NAME: {meta['name']}")
                lines += hintLines("TABLEFIELD_HINT", meta.get("hint", ""))
                if meta.get("selector"):
                    lines.append(f"-- [UI] TABLEFIELD_SELECTOR: {meta['selector']}")
                lines.append(f"    {key} = {value},")
            lines.append("}")
        else:
            lines.append(f"{prefix}{var.name} = {var.value}")
    return "\n".join(lines)


class FileState:
    def __init__(self, path, content, encoding, line_ending):
        self.path, self.name = path, os.path.basename(path)
        self.encoding, self.line_ending = encoding, line_ending
        self.original_content = content
        self.variables, self.order, self.categories = parseLua(content)
        self.selected_name = None
        self.has_changes = False
        self.expanded = set()

    def ordered(self):
        return [self.variables[n] for n in self.order]

    def selected(self):
        return self.variables.get(self.selected_name)

    def allCAT(self):
        return self.categories + [v.section for v in self.ordered() if v.section not in self.categories]

    def CATColor(self, name):
        if name == "System":
            return "#5b6272"
        return ["#5b9dff", "#39d98a", "#ff9f43", "#b389ff", "#3ee0d6", "#ff5d6c", "#ffd166", "#8f6bff"][self.categories.index(name) % 8] if name in self.categories else "#5b9dff"


# UI Widgets
class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.window, self.job = widget, text, None, None
        widget.bind("<Enter>", self.schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<ButtonPress>", self.hide, add="+")

    def schedule(self, _event=None):
        self.hide()
        self.job = self.widget.after(500, self.show)

    def show(self):
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry(f"+{self.widget.winfo_rootx()}+{self.widget.winfo_rooty() + self.widget.winfo_height() + 6}")
        tk.Label(self.window, text=self.text, bg="#1d212b", fg="#eef0f4", font=("Segoe UI", 8), padx=8, pady=3, highlightthickness=1, highlightbackground="#232733").pack()

    def hide(self, _event=None):
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.window:
            self.window.destroy()
            self.window = None


class Btn(tk.Label):
    def __init__(self, parent, text, command, primary=False, mini=False, bg=None, tip=""):
        if primary:
            normal, hover, fg = "#5b9dff", "#7fb2ff", "#08111f"
        elif mini:
            normal, hover, fg = bg or parent.cget("bg"), "#1d212b", "#9099ab"
        else:
            normal, hover, fg = "#181b23", "#1d212b", "#9099ab"
        super().__init__(parent, text=text, bg=normal, fg=fg, cursor="hand2", bd=0, font=("Segoe UI", 10) if mini else ("Segoe UI", 9, "bold"), padx=3 if mini else 12, pady=0 if mini else 6, highlightthickness=0 if mini or primary else 1, highlightbackground="#232733")
        self.command = command
        self.bind("<Enter>", lambda e: self.configure(bg=hover))
        self.bind("<Leave>", lambda e: self.configure(bg=normal))
        self.bind("<Button-1>", lambda e: self.command and self.command())
        if tip:
            Tooltip(self, tip)


class Toggle(tk.Canvas):
    def __init__(self, parent, value=False, command=None, bg=None):
        super().__init__(parent, width=38, height=20, bg=bg or parent.cget("bg"), highlightthickness=0, bd=0, cursor="hand2")
        self.value, self.command = bool(value), command
        self.bind("<Button-1>", self.onClick)
        self.draw()

    def draw(self):
        self.delete("all")
        self.create_rectangle(0, 0, 37, 19, fill="#2fb579" if self.value else "#14161d", outline="#2fb579" if self.value else "#232733")
        x = 21 if self.value else 3
        self.create_rectangle(x, 3, x + 14, 17, fill="#ffffff" if self.value else "#dfe3ea", outline="")

    def onClick(self, _event):
        self.set(not self.value)
        if self.command:
            self.command(self.value)

    def set(self, value):
        self.value = bool(value)
        self.draw()


class ScrollFrame(tk.Frame):
    def __init__(self, parent, bg, on_resize=None):
        super().__init__(parent, bg=bg)
        self.on_resize = on_resize
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0, yscrollincrement=20)
        scrollbar = ttk.Scrollbar(self, orient="vertical", style="Lunex.Vertical.TScrollbar", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=(0, 0, e.width, e.height)))
        self.canvas.bind("<Configure>", self.onCanvasResize)

    def onCanvasResize(self, event):
        self.canvas.itemconfigure(self.window, width=event.width)
        if self.on_resize:
            self.on_resize(event.width)

    def scroll(self, steps):
        first, last = self.canvas.yview()
        if first > 0 or last < 1:
            self.canvas.yview_scroll(steps, "units")

    def clear(self):
        self.canvas.yview_moveto(0)
        for widget in self.inner.winfo_children():
            widget.destroy()


def bindTree(widget, event, func):
    if isinstance(widget, (tk.Entry, ttk.Combobox, Toggle, Btn)):
        return
    widget.bind(event, func, add="+")
    for child in widget.winfo_children():
        bindTree(child, event, func)


def findParent(widget, test):
    while widget is not None:
        if test(widget):
            return widget
        widget = getattr(widget, "master", None)
    return None


def widgetAt(root, x, y):
    try:
        return root.winfo_containing(x, y)
    except (KeyError, tk.TclError):
        return None


class LunexApp:
    def __init__(self, root):
        self.root = root
        self.file = None
        self.card_widgets = {}
        self.inspector_setter = None
        self.inspector_visible = False
        self.panels = []
        self.counts = {}
        self.jobs = {}
        self.toast_label = None
        self.drag = None
        self.syncing = False
        self.tag_color = "BLUE"

        root.title("Lunex Editor")
        root.geometry("1280x720")
        root.minsize(800, 600)
        root.configure(bg="#0b0c10")
        root.protocol("WM_DELETE_WINDOW", self.onClose)
        if HAS_DND:
            root.drop_target_register(DND_FILES)
            root.dnd_bind("<<Drop>>", self.onDrop)

        self.logo_home = loadLogo(96)
        self.logo_icon = loadLogo(64)
        icon = BaseDir / "lunexRes" / "lunex.ico"
        try:
            if icon.is_file() and sys.platform.startswith("win"):
                root.iconbitmap(str(icon))
            elif self.logo_icon:
                root.iconphoto(True, self.logo_icon)
        except tk.TclError:
            pass

        self.setStyle()

        self.bar = tk.Frame(root, bg="#0f1116", height=38)
        self.bar.pack(fill="x")
        self.bar.pack_propagate(False)
        tk.Frame(root, bg="#232733", height=1).pack(fill="x")

        self.paned = tk.PanedWindow(root, orient="horizontal", sashwidth=5, sashrelief="flat", bd=0, bg="#232733")
        self.paned.pack(fill="both", expand=True)
        self.main_scroll = ScrollFrame(self.paned, "#0b0c10", on_resize=lambda w: self.later("resize", 60, self.layoutGrids))
        self.paned.add(self.main_scroll, minsize=360, stretch="always")

        self.inspector_frame = tk.Frame(self.paned, bg="#0f1116")
        tk.Label(self.inspector_frame, text="INSPECTOR", font=("Segoe UI", 8, "bold"), bg="#0f1116", fg="#eef0f4", padx=16, pady=12, anchor="w").pack(fill="x")
        tk.Frame(self.inspector_frame, bg="#5b9dff", height=2).pack(fill="x")
        self.inspector_scroll = ScrollFrame(self.inspector_frame, "#0f1116")
        self.inspector_scroll.pack(fill="both", expand=True)

        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            root.bind_all(sequence, self.onWheel)
        root.bind("<Control-s>", lambda e: self.saveFile())
        root.bind("<Control-o>", lambda e: self.openFileTXT())
        root.bind("<Control-w>", lambda e: self.closeFile())

        self.watched_found = findFiles()
        self.renderUI()

        for arg in sys.argv[1:]:
            if os.path.isfile(arg):
                self.openPath(arg)

    def setStyle(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Lunex.TCombobox", fieldbackground="#14161d", background="#1d212b", foreground="#eef0f4", arrowcolor="#9099ab",
                        bordercolor="#232733", lightcolor="#232733", darkcolor="#232733", selectbackground="#14161d", selectforeground="#eef0f4", padding=2)
        style.map("Lunex.TCombobox", fieldbackground=[("readonly", "#14161d"), ("focus", "#181b23")], foreground=[("readonly", "#eef0f4")],
                  selectbackground=[("readonly", "#14161d")], selectforeground=[("readonly", "#eef0f4")], background=[("active", "#1d212b")], arrowcolor=[("active", "#eef0f4")])
        style.layout("Lunex.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        style.configure("Lunex.Vertical.TScrollbar", background="#2a2f3b", troughcolor="#0f1116", bordercolor="#0f1116", lightcolor="#2a2f3b", darkcolor="#2a2f3b", width=9)
        style.map("Lunex.Vertical.TScrollbar", background=[("active", "#3a4152")], lightcolor=[("active", "#3a4152")], darkcolor=[("active", "#3a4152")])

        for option, value in (("background", "#0f1116"), ("foreground", "#eef0f4"), ("selectBackground", "#5b9dff"), ("selectForeground", "#08111f")):
            self.root.option_add(f"*TCombobox*Listbox.{option}", value)
        self.root.option_add("*TCombobox*Listbox.font", ("Segoe UI", 9))
        self.root.bind_class("TCombobox", "<MouseWheel>", lambda e: (self.onWheel(e), "break")[1])

    def onWheel(self, event):
        button = getattr(event, "num", 0)
        steps = -3 if button == 4 else 3 if button == 5 else (-3 if event.delta > 0 else 3)
        scroll = findParent(widgetAt(self.root, event.x_root, event.y_root), lambda w: isinstance(w, ScrollFrame))
        if scroll:
            scroll.scroll(steps)

    def later(self, name, delay, func):
        if self.jobs.get(name):
            self.root.after_cancel(self.jobs[name])
        self.jobs[name] = self.root.after(delay, func)

    def refresh(self):
        self.renderInspec()
        self.renderMainViewer(keep_scroll=True)

    def markChanged(self):
        if self.file and not self.file.has_changes:
            self.file.has_changes = True
            self.renderBar()

    def openFileTXT(self):
        path = filedialog.askopenfilename(parent=self.root, title="Open Lua file", filetypes=[("Lua files", "*.lua *.hks *.txt"), ("All files", "*.*")])
        if path:
            self.openPath(path)

    def onDrop(self, event):
        for path in self.root.tk.splitlist(event.data):
            if path.lower().endswith((".lua", ".hks", ".txt")):
                self.openPath(path)
                break

    def openPath(self, path):
        path = os.path.abspath(path)
        if self.file and norm(self.file.path) == norm(path):
            return
        if not self.confirmClose():
            return
        try:
            self.file = FileState(path, *readTXTFile(path))
        except Exception:
            messagebox.showerror("Lunex", "Error reading file.", parent=self.root)
            return
        updateTempFiles(path)
        self.renderUI()
        self.toast(f'"{self.file.name}" loaded with {len(self.file.order)} variables')

    def closeFile(self):
        if self.file and self.confirmClose():
            self.file = None
            self.renderUI()

    def confirmClose(self):
        return not (self.file and self.file.has_changes) or messagebox.askyesno("Unsaved changes", "You have unsaved changes.\n      Close anyway?", parent=self.root)

    def onClose(self):
        if self.confirmClose():
            self.root.destroy()

    def varCount(self, path):
        try:
            key = (path, os.path.getmtime(path))
            if key not in self.counts:
                self.counts[key] = len(parseLua(readTXTFile(path)[0])[1])
            return self.counts[key]
        except Exception:
            return None

    def saveFile(self):
        file = self.file
        if not file:
            return
        try:
            section = buildVarTXT(file).lstrip("\n")
            if ReadBlockFormat.search(file.original_content):
                new_content = ReadBlockFormat.sub(lambda m: m.group(1) + section + "\n\n" + m.group(3), file.original_content, count=1)
            else:
                if not messagebox.askyesno("No READ VARIABLES section", f'"{file.name}" has no --// READ VARIABLES block.\n\nSaving will replace the ENTIRE file with the variables section (a .backup copy is kept). Continue?', parent=self.root):
                    return
                new_content = f"--// READ VARIABLES\n{section}\n\n--// END READ VARIABLES\n"

            if os.path.exists(file.path):
                shutil.copy2(file.path, file.path + ".backup")
            with open(file.path, "w", encoding=file.encoding, newline="") as out:
                out.write(new_content.replace("\n", file.line_ending))

            file.original_content = new_content
            file.has_changes = False
            self.renderBar()
            self.toast(f"Changes saved in {file.name}")
        except Exception as error:
            messagebox.showerror("Lunex", f"Error saving:\n{error}", parent=self.root)

    def renderUI(self):
        show = self.file is not None
        if show and not self.inspector_visible:
            self.paned.add(self.inspector_frame, width=320, minsize=260, stretch="never")
        elif not show and self.inspector_visible:
            self.paned.forget(self.inspector_frame)
        self.inspector_visible = show
        self.renderBar()
        self.renderMainViewer()
        self.renderInspec()

    def renderBar(self):
        for widget in self.bar.winfo_children():
            widget.destroy()
        file = self.file
        if not file:
            return
        tk.Frame(self.bar, bg="#ff9f43" if file.has_changes else "#39d98a", width=8, height=8).pack(side="left", padx=(16, 6))
        tk.Label(self.bar, text=file.name, font=("Segoe UI", 9), bg="#0f1116", fg="#eef0f4").pack(side="left")
        Btn(self.bar, "Close", self.closeFile, tip="Close file (Ctrl+W)").pack(side="left", padx=(1015, 12), pady=5)
        Btn(self.bar, "Save", self.saveFile, primary=True, tip="Save changes (Ctrl+S)").pack(side="left", pady=5)

    def layoutGrids(self, force=False):
        available = self.main_scroll.canvas.winfo_width() - 76
        if available < 50:
            return
        for panel in self.panels:
            grid, cards, minimal = panel["grid"], panel["cards"], panel["minimal"]
            columns = max(1, available // minimal)
            if columns == panel["columns"] and not force:
                continue
            for column in range(max(columns, panel["columns"])):
                active = column < columns
                grid.grid_columnconfigure(column, weight=1 if active else 0, uniform="card" if active else "", minsize=minimal - 10 if active else 0)
            for i, card in enumerate(cards):
                card.grid(row=i // columns, column=i % columns, sticky="nsew", padx=5, pady=5)
            panel["columns"] = columns

    def addGrid(self, grid, cards, minimal):
        self.panels.append({"grid": grid, "cards": cards, "minimal": minimal, "columns": 0})

    def scheduleRender(self, delay=300):
        self.later("render", delay, lambda: self.renderMainViewer(keep_scroll=True))

    def renderMainViewer(self, keep_scroll=False):
        canvas = self.main_scroll.canvas
        position = canvas.yview()[0] if keep_scroll else 0
        self.main_scroll.clear()
        self.panels, self.card_widgets = [], {}
        inner = self.main_scroll.inner
        file = self.file

        if not file:
            self.renderHome(inner)
        elif not file.variables:
            box = tk.Frame(inner, bg="#0b0c10")
            box.pack(expand=True, fill="both", pady=(120, 0))
            tk.Label(box, text="📄", font=("Segoe UI", 28), bg="#0b0c10", fg="#5b6272").pack(pady=(0, 10))
            tk.Label(box, text="Empty", font=("Segoe UI", 13, "bold"), bg="#0b0c10", fg="#9099ab").pack()
            tk.Label(box, text="The file does not contain configurable variables.", font=("Segoe UI", 9), bg="#0b0c10", fg="#5b6272", wraplength=360).pack(pady=(6, 0))
        else:
            groups = {}
            for var in file.ordered():
                groups.setdefault(var.section, []).append(var)
            wrap = tk.Frame(inner, bg="#0b0c10")
            wrap.pack(fill="x", padx=28, pady=(22, 60))
            for category in sortCAT(groups):
                self.buildPanel(wrap, category, groups[category])

        self.layoutGrids(True)
        inner.update_idletasks()
        canvas.yview_moveto(position)

    def renderHome(self, parent):
        detected = [p for p in self.watched_found if os.path.isfile(p)]
        known = {norm(p) for p in detected}
        recents = [p for p in recentFiles() if norm(p) not in known]

        wrap = tk.Frame(parent, bg="#0b0c10")
        wrap.pack(fill="x", padx=28, pady=(34, 60))
        head = tk.Frame(wrap, bg="#0b0c10")
        head.pack(fill="x", pady=(0, 26), padx=10)
        if self.logo_home:
            tk.Label(head, image=self.logo_home, bg="#0b0c10").pack(side="left", padx=(0, 20))
        titles = tk.Frame(head, bg="#0b0c10")
        titles.pack(side="left")
        tk.Label(titles, text="Lunex", font=("Segoe UI", 28, "bold"), bg="#0b0c10", fg="#eef0f4").pack(anchor="w")
        tk.Label(titles, text=f"{len(detected) + len(recents)} files", font=("Segoe UI", 10), bg="#0b0c10", fg="#5b6272").pack(anchor="w")

        grid = tk.Frame(wrap, bg="#0b0c10")
        grid.pack(fill="x", padx=10)
        cards = [self.actionBlock(grid, "+", "Add File", "#39d98a", self.openFileTXT),
                 self.actionBlock(grid, "↻", "Rescan Files", "#5b9dff", self.rescan)]
        cards += [self.fileBlock(grid, p) for p in detected]
        cards += [self.fileBlock(grid, p, True) for p in recents]
        self.addGrid(grid, cards, 210)

    def rescan(self):
        self.watched_found = findFiles()
        self.renderMainViewer()
        self.toast(f"{len(self.watched_found)} watched file(s) found")

    def baseBlock(self, parent, command):
        block = tk.Frame(parent, bg="#14161d", height=150, cursor="hand2", highlightthickness=1, highlightbackground="#232733")
        block.pack_propagate(False)
        block.bind("<Enter>", lambda e: block.configure(highlightbackground="#5b9dff"))
        block.bind("<Leave>", lambda e: None if findParent(widgetAt(block, e.x_root, e.y_root), lambda w: w is block)
                   else block.configure(highlightbackground="#232733"))
        return block

    def actionBlock(self, parent, glyph, text, color, command):
        block = self.baseBlock(parent, command)
        center = tk.Frame(block, bg="#14161d")
        center.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(center, text=glyph, font=("Segoe UI", 34), bg="#14161d", fg=color).pack()
        tk.Label(center, text=text, font=("Segoe UI", 11, "bold"), bg="#14161d", fg="#9099ab").pack(pady=(6, 0))
        bindTree(block, "<Button-1>", lambda e: command())
        return block

    def fileBlock(self, parent, path, removable=False):
        block = self.baseBlock(parent, None)
        inner = tk.Frame(block, bg="#14161d")
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(inner, text="📄", font=("Segoe UI", 22), bg="#14161d", fg="#9099ab").pack(anchor="w")
        tk.Label(inner, text=os.path.basename(path), font=("Segoe UI", 11, "bold"), bg="#14161d", fg="#eef0f4", wraplength=160, justify="left", anchor="w").pack(fill="x", pady=(8, 2))
        tk.Label(inner, text=shortPath(path), font=("Segoe UI", 8), bg="#14161d", fg="#5b6272", anchor="w").pack(fill="x")
        count = self.varCount(path)
        tk.Label(inner, text="—" if count is None else f"{count} vars" if count else "No variables", font=("Segoe UI", 7, "bold"), bg="#16233a", fg="#5b9dff", padx=6, pady=2).pack(side="bottom", anchor="w")
        if removable:
            Btn(block, "×", lambda: (updateTempFiles(path, add=False), self.renderMainViewer()), mini=True, bg="#14161d", tip="Remove from recents").place(relx=1.0, x=-6, y=6, anchor="ne")
        bindTree(block, "<Button-1>", lambda e: self.openPath(path))
        return block

    def buildPanel(self, parent, category, variables):
        color = self.file.CATColor(category)
        panel = tk.Frame(parent, bg="#14161d")
        panel.pack(fill="x", pady=(0, 18))
        panel.lunex_category = category

        head = tk.Frame(panel, bg="#14161d")
        head.pack(fill="x", padx=16, pady=(12, 4))
        tk.Frame(head, bg=color, width=9, height=9).pack(side="left", padx=(0, 10))
        tk.Label(head, text=category.upper(), font=("Segoe UI", 10, "bold"), bg="#14161d", fg=color).pack(side="left")
        tk.Label(head, text=f"{len(variables)} variables", font=("Segoe UI", 8), bg="#14161d", fg="#5b6272").pack(side="left", padx=8)
        tk.Frame(panel, bg="#1a1d26", height=1).pack(fill="x")

        for tables, minimal in ((False, 210), (True, 420)):
            items = [v for v in variables if (v.type == "table") == tables]
            if items:
                grid = tk.Frame(panel, bg="#14161d")
                grid.pack(fill="x", padx=10, pady=(10, 0))
                grid.lunex_category = category
                self.addGrid(grid, [self.createCard(grid, v) for v in items], minimal)
        tk.Frame(panel, bg="#14161d", height=10).pack()

    def tagColor(self, var, tag):
        name = var.tag_colors.get(tag.upper(), "")
        return name if name.startswith("#") else t_TagColors.get(name, "#5b6272")

    def tagBadge(self, parent, var, tag, **pack):
        label = tk.Label(parent, text=tag.upper(), font=("Segoe UI", 7, "bold"), bg=self.tagColor(var, tag), fg="#0b0c10", padx=5)
        label.pack(side="left", **pack)

    def createCard(self, parent, var):
        bg = "#1d212b"
        file = self.file
        wrap = 380 if var.type == "table" else 170
        card = tk.Frame(parent, bg=bg, highlightthickness=1, highlightbackground="#5b9dff" if file.selected_name == var.name else "#1a1d26")
        body = tk.Frame(card, bg=bg)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        name_label = tk.Label(body, text=var.ui_name, font=("Segoe UI", 10, "bold"), fg="#eef0f4", bg=bg, justify="left", anchor="w", wraplength=wrap)
        name_label.pack(fill="x")
        if var.tags:
            tags = tk.Frame(body, bg=bg)
            tags.pack(fill="x", pady=(5, 0))
            for tag in var.tags[:3]:
                self.tagBadge(tags, var, tag, padx=(0, 4))
        if var.hint:
            tk.Label(body, text=var.hint, font=("Segoe UI", 8), fg="#5b6272", bg=bg, wraplength=wrap, justify="left", anchor="w").pack(fill="x", pady=(6, 0))

        controls = tk.Frame(body, bg=bg)
        controls.pack(side="bottom", fill="x", pady=(8, 0))
        entry = {"frame": card, "name_label": name_label, "set_value": None}

        if var.type == "table":
            fields = tk.Frame(body, bg=bg)
            button = Btn(controls, "Show", None)
            button.command = lambda: self.showTable(var, fields, button, var.name not in file.expanded)
            button.pack(fill="x")
            self.showTable(var, fields, button, var.name in file.expanded)
        else:
            widget, entry["set_value"] = self.valueControl(controls, var.type, var.value, lambda v: self.onValue(var, v, "card"), var.selector)
            if var.type == "boolean":
                widget.pack(side="right")
            elif var.type == "selector":
                widget.pack(fill="x", ipady=5)
            else:
                widget.pack(side="right", ipady=5)
        self.card_widgets[var.name] = entry

        system = var.section == "System"
        bindTree(card, "<Button-1>", lambda e: setattr(self, "drag", {"name": var.name, "x": e.x_root, "y": e.y_root, "active": False, "ghost": None, "system": system}))
        bindTree(card, "<B1-Motion>", self.onCardMotion)
        bindTree(card, "<ButtonRelease-1>", self.onCardRelease)
        return card

    def showTable(self, var, fields, button, show):
        for widget in fields.winfo_children():
            widget.destroy()
        if show:
            self.file.expanded.add(var.name)
            self.tableFields(fields, var)
            fields.pack(fill="x", pady=(8, 0))
        else:
            self.file.expanded.discard(var.name)
            fields.pack_forget()
        button.configure(text="Hide" if show else "Show")

    def tableFields(self, parent, var):
        bg = parent.cget("bg")
        if not var.value:
            tk.Label(parent, text="Empty table", font=("Segoe UI", 9), bg=bg, fg="#5b6272").pack(anchor="w")
        for key, value in var.value.items():
            meta = var.table_fields.get(key, {})
            kind = "selector" if meta.get("selector") else "boolean" if isBool(value) else "text"
            row = tk.Frame(parent, bg=bg)
            row.pack(fill="x", pady=(4, 0))
            tk.Label(row, text=meta.get("name") or key, font=("Segoe UI", 9), bg=bg, fg="#9099ab").pack(side="left")
            widget, _ = self.valueControl(row, kind, value, lambda v, k=key: self.setTableField(var, k, v), parseSelect(meta.get("selector")), width=14)
            widget.pack(side="right", ipady=0 if kind != "text" else 2)
            if meta.get("hint"):
                tk.Label(parent, text=meta["hint"], font=("Segoe UI", 8), bg=bg, fg="#5b6272", wraplength=360, justify="left", anchor="w").pack(fill="x")

    def setTableField(self, var, key, value):
        var.value[key] = value
        self.markChanged()

    def setEntry(self, parent, text_var=None, mono=False, justify="left", width=20, bg=None, fg=None, flat=False):
        bg = bg or "#14161d"
        return tk.Entry(parent, textvariable=text_var, width=width, bg=bg, fg=fg or "#eef0f4", insertbackground="#eef0f4", relief="flat", bd=0, highlightthickness=0 if flat else 1, 
            highlightbackground="#232733", highlightcolor="#5b9dff", disabledbackground=bg, disabledforeground="#5b6272", font=("Consolas" if mono else "Segoe UI", 9), justify=justify)

    def valueControl(self, parent, kind, value, onChange, options=None, justify="right", width=20):
        if kind == "boolean":
            toggle = Toggle(parent, value.lower() == "true", bg=parent.cget("bg"), command=lambda v: onChange("true" if v else "false"))
            return toggle, lambda v: toggle.set(v.lower() == "true")

        if kind == "selector":
            keys = list(options)
            combo = ttk.Combobox(parent, values=[options[k] for k in keys], state="readonly", style="Lunex.TCombobox", font=("Segoe UI", 9))

            def setSelector(new_value):
                if new_value in keys:
                    combo.current(keys.index(new_value))

            def onSelect(_event):
                combo.selection_clear()
                onChange(keys[combo.current()])

            setSelector(value)
            combo.bind("<<ComboboxSelected>>", onSelect)
            return combo, setSelector

        text_var = tk.StringVar(value=value)
        entry = self.setEntry(parent, text_var, justify=justify, width=width)

        def setText(new_value):
            if text_var.get() != new_value:
                self.syncing = True
                text_var.set(new_value)
                self.syncing = False

        text_var.trace_add("write", lambda *_: None if self.syncing else onChange(text_var.get()))
        return entry, setText

    def onValue(self, var, value, source):
        var.value = value
        self.markChanged()
        if source != "card":
            widgets = self.card_widgets.get(var.name)
            if widgets and widgets["set_value"]:
                widgets["set_value"](value)
        if source != "inspector" and self.file.selected_name == var.name and self.inspector_setter:
            self.inspector_setter(value)

    def selectVar(self, name):
        old, self.file.selected_name = self.file.selected_name, name
        for var_name in (old, name):
            widgets = self.card_widgets.get(var_name)
            if widgets:
                widgets["frame"].configure(highlightbackground="#5b9dff" if var_name == name else "#1a1d26")
        self.renderInspec()

    def onCardMotion(self, event):
        drag = self.drag
        if not drag or drag["system"]:
            return
        if not drag["active"]:
            if abs(event.x_root - drag["x"]) + abs(event.y_root - drag["y"]) < 8:
                return
            drag["active"] = True
            ghost = tk.Toplevel(self.root)
            ghost.wm_overrideredirect(True)
            try:
                ghost.attributes("-alpha", 0.85)
            except tk.TclError:
                pass
            tk.Label(ghost, text=self.file.variables[drag["name"]].ui_name, bg="#5b9dff", fg="#08111f", font=("Segoe UI", 9, "bold"), padx=10, pady=4).pack()
            drag["ghost"] = ghost
            self.root.configure(cursor="fleur")
        drag["ghost"].geometry(f"+{event.x_root + 14}+{event.y_root + 14}")

    def onCardRelease(self, event):
        drag, self.drag = self.drag, None
        if not drag:
            return
        if not drag["active"]:
            self.selectVar(drag["name"])
            return
        drag["ghost"].destroy()
        self.root.configure(cursor="")
        target = findParent(widgetAt(self.root, event.x_root, event.y_root), lambda w: hasattr(w, "lunex_category"))
        if target:
            self.moveVar(drag["name"], target.lunex_category)

    def moveVar(self, name, category):
        var = self.file.variables.get(name)
        if not var or var.section == category:
            return
        if category == "System":
            self.toast("Cannot move variables to System category")
            return
        var.section = category
        if category not in self.file.categories:
            self.file.categories.append(category)
        self.markChanged()
        self.refresh()
        self.toast(f'"{var.ui_name}" moved to "{category}"')

    def inspectorLabel(self, parent, text, heading=False):
        if heading:
            tk.Label(parent, text=text, font=("Segoe UI", 8, "bold"), bg="#0f1116", fg="#5b6272", anchor="w").pack(fill="x", pady=(14, 8))
        else:
            tk.Label(parent, text=text, font=("Segoe UI", 9), bg="#0f1116", fg="#9099ab", anchor="w").pack(fill="x", pady=(0, 4))

    def renderInspec(self):
        self.inspector_scroll.clear()
        self.inspector_setter = None
        inner = self.inspector_scroll.inner
        var = self.file.selected() if self.file else None
        if not var:
            tk.Label(inner, text="Select a variable in the grid to view and edit its details here.", font=("Segoe UI", 10), bg="#0f1116", fg="#5b6272", wraplength=240).pack(padx=20, pady=(60, 0))
            return

        system = var.section == "System"
        lock = "  🔒" if system else ""
        pad = tk.Frame(inner, bg="#0f1116")
        pad.pack(fill="x", padx=16, pady=14)

        row = tk.Frame(pad, bg="#0f1116")
        row.pack(fill="x")
        title = tk.Label(row, text=var.ui_name + lock, font=("Segoe UI", 13, "bold"), bg="#0f1116", fg="#eef0f4", anchor="w", wraplength=150, justify="left")
        title.pack(side="left", fill="x", expand=True)
        tk.Label(row, text=var.type.upper(), font=("Segoe UI", 8, "bold"), bg="#16233a", fg="#5b9dff", padx=8, pady=2).pack(side="right")

        self.inspectorLabel(pad, "Display name", heading=True)
        name_var = tk.StringVar(value=var.ui_name)

        def onName(*_):
            var.ui_name = name_var.get()
            title.configure(text=var.ui_name + lock)
            widgets = self.card_widgets.get(var.name)
            if widgets:
                widgets["name_label"].configure(text=var.ui_name)
            self.markChanged()

        name_var.trace_add("write", onName)
        self.setEntry(pad, name_var).pack(fill="x", ipady=2, pady=(0, 10))

        self.inspectorLabel(pad, "Variable name")
        name_entry = self.setEntry(pad, mono=True)
        name_entry.insert(0, var.name)
        name_entry.configure(state="disabled")
        name_entry.pack(fill="x", ipady=2, pady=(0, 10))

        self.inspectorLabel(pad, "Category")
        categories = [c for c in sortCAT(self.file.allCAT()) if c != "System" or c == var.section]
        combo = ttk.Combobox(pad, values=categories, state="disabled" if system else "readonly", style="Lunex.TCombobox", font=("Segoe UI", 9))
        combo.current(categories.index(var.section))
        combo.pack(fill="x")
        combo.bind("<<ComboboxSelected>>", lambda e: (combo.selection_clear(), self.moveVar(var.name, combo.get())))

        self.inspectorLabel(pad, "VALUE", heading=True)
        if var.type == "table":
            tk.Label(pad, text=f"{len(var.value)} fields — expand the card to edit them.", font=("Segoe UI", 9), bg="#0f1116", fg="#5b6272", anchor="w").pack(fill="x")
        else:
            widget, self.inspector_setter = self.valueControl(pad, var.type, var.value, lambda v: self.onValue(var, v, "inspector"), var.selector, justify="left")
            if var.type == "boolean":
                widget.pack(anchor="w")
            else:
                widget.pack(fill="x", ipady=0 if var.type == "selector" else 2)
            if var.type == "selector":
                self.inspecSelector(pad, var, widget)

        self.inspectorLabel(pad, "DESCRIPTION", heading=True)
        hint_text = tk.Text(pad, height=3, bg="#14161d", fg="#eef0f4", insertbackground="#eef0f4", relief="flat", bd=0, highlightthickness=1, highlightbackground="#232733", highlightcolor="#5b9dff", font=("Segoe UI", 10), wrap="word", padx=8, pady=6)
        hint_text.insert("1.0", var.hint)
        hint_text.pack(fill="x")

        def onHint(_event):
            var.hint = hint_text.get("1.0", "end-1c")
            self.markChanged()
            self.scheduleRender(500)

        hint_text.bind("<KeyRelease>", onHint)

        self.inspectorLabel(pad, "TAGS", heading=True)
        self.inspecTags(pad, var)

    def inspecSelector(self, pad, var, combo):
        self.inspectorLabel(pad, "SELECTOR OPTIONS", heading=True)
        rows_frame = tk.Frame(pad, bg="#0f1116")
        rows_frame.pack(fill="x")
        rows = []

        def rebuild(*_):
            var.selector = {k.get().strip(): v.get().strip() for k, v in rows if k.get().strip()}
            keys = list(var.selector)
            combo.configure(values=[var.selector[k] for k in keys])
            if var.value in keys:
                combo.current(keys.index(var.value))
            self.markChanged()
            self.scheduleRender(400)

        for key, label in var.selector.items():
            row = tk.Frame(rows_frame, bg="#14161d", highlightthickness=1, highlightbackground="#232733")
            row.pack(fill="x", pady=2)
            key_var, label_var = tk.StringVar(value=key), tk.StringVar(value=label)
            rows.append((key_var, label_var))
            self.setEntry(row, key_var, mono=True, width=8, fg="#5b9dff", flat=True).pack(side="left", padx=(6, 2), pady=4)
            self.setEntry(row, label_var, flat=True).pack(side="left", fill="x", expand=True, padx=2)
            Btn(row, "×", lambda k=key: self.changeSelector(var, k), mini=True, bg="#14161d", tip="Remove option").pack(side="right", padx=4)
            key_var.trace_add("write", rebuild)
            label_var.trace_add("write", rebuild)

        Btn(pad, "+ add option", lambda: self.changeSelector(var)).pack(fill="x", pady=(6, 0))

    def changeSelector(self, var, remove_key=None):
        if remove_key is None:
            number = 0
            while f"NEW_{number}" in var.selector:
                number += 1
            var.selector[f"NEW_{number}"] = "New Option"
        else:
            var.selector.pop(remove_key, None)
        self.markChanged()
        self.refresh()

    def inspecTags(self, pad, var):
        chips = tk.Frame(pad, bg="#0f1116")
        chips.pack(fill="x", pady=(0, 8))
        if not var.tags:
            tk.Label(chips, text="No tags defined", font=("Segoe UI", 9), bg="#0f1116", fg="#5b6272").pack(anchor="w")
        for index, tag in enumerate(var.tags):
            color = self.tagColor(var, tag)
            chip = tk.Frame(chips, bg=color)
            chip.pack(side="left", padx=(0, 6))
            self.tagBadge(chip, var, tag, pady=2)
            Btn(chip, "×", lambda i=index: self.changeTag(var, index=i), mini=True, bg=color, tip="Remove tag").pack(side="left", padx=(0, 3))

        box = tk.Frame(pad, bg="#14161d", highlightthickness=1, highlightbackground="#232733")
        box.pack(fill="x")
        input_row = tk.Frame(box, bg="#14161d")
        input_row.pack(fill="x", padx=8, pady=(8, 6))
        text_var = tk.StringVar()
        entry = self.setEntry(input_row, text_var, bg="#181b23")
        entry.pack(side="left", fill="x", expand=True, ipady=2)
        Btn(input_row, "+", lambda: self.changeTag(var, text=text_var.get()), mini=True, bg="#14161d", tip="Add tag").pack(side="right", padx=(6, 0))
        entry.bind("<Return>", lambda e: self.changeTag(var, text=text_var.get()))

        swatch_row = tk.Frame(box, bg="#14161d")
        swatch_row.pack(fill="x", padx=8, pady=(0, 8))
        swatches = {}

        def pickColor(name):
            self.tag_color = name
            for swatch_name, swatch in swatches.items():
                swatch.configure(highlightbackground="#eef0f4" if swatch_name == name else "#14161d")

        for name, color in t_TagColors.items():
            swatch = tk.Frame(swatch_row, bg=color, width=18, height=18, cursor="hand2", highlightthickness=2, highlightbackground="#eef0f4" if name == self.tag_color else "#14161d")
            swatch.pack(side="left", padx=2)
            swatch.bind("<Button-1>", lambda e, n=name: pickColor(n))
            swatches[name] = swatch
            Tooltip(swatch, name.title())

    def changeTag(self, var, text=None, index=None):
        if index is not None:
            var.tag_colors.pop(var.tags.pop(index).upper(), None)
        else:
            text = (text or "").strip()
            if not text:
                return
            var.tags.append(text)
            var.tag_colors[text.upper()] = self.tag_color
        self.markChanged()
        self.refresh()

    def toast(self, message):
        if self.toast_label is None:
            self.toast_label = tk.Label(self.root, bg="#1d212b", fg="#eef0f4", font=("Segoe UI", 10), padx=18, pady=9, highlightthickness=1, highlightbackground="#232733")
        self.toast_label.configure(text=message)
        self.toast_label.place(relx=0.5, rely=1.0, y=-26, anchor="s")
        self.toast_label.lift()
        self.later("toast", 3000, self.toast_label.place_forget)


def main():
    try:
        root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        LunexApp(root)
        root.mainloop()
    except Exception:
        error = traceback.format_exc()
        try:
            messagebox.showerror("Lunex", error)
        except Exception:
            print(error)


if __name__ == "__main__":
    main()
