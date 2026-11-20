// Tempra RMM console: the agent context menu (right click on an agent row)
// and opening the action named in the address (#act-...). The menu items
// come from a <template> rendered by the server, already translated and
// limited to what the operator may do; this script only shows them.
(function () {
  "use strict";

  // Open the <details> an address points at (e.g. #act-reboot-reboot).
  function openTarget() {
    if (!location.hash) return;
    var el = document.getElementById(location.hash.slice(1));
    if (!el) return;
    // Open the element and every <details> around it.
    for (var d = el; d; d = d.parentElement) {
      if (d.tagName === "DETAILS") d.open = true;
    }
    el.scrollIntoView({ block: "start" });
  }
  // The full agent page is long: each section (an <h2> and what follows
  // it, up to the next one) folds away. A section opens by itself when it
  // reports a problem, which its title counts; otherwise it stays as the
  // operator left it last time (remembered per section in this browser). A
  // bar on top jumps to a section and expands or collapses them all.
  var sections = document.querySelector("div.sections");
  if (sections) {
    var groups = [], cur = null;
    Array.prototype.slice.call(sections.children).forEach(function (child) {
      if (child.tagName === "H2") {
        cur = document.createElement("details");
        cur.className = "group section";
        var sum = document.createElement("summary");
        child.before(cur);
        sum.appendChild(child);
        cur.appendChild(sum);
        groups.push(cur);
      } else if (child.matches("details.group")) {
        cur = null;
        groups.push(child);
      } else if (cur) {
        cur.appendChild(child);
      }
    });
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem("agent.sections") || "{}") || {}; } catch (e) { saved = {}; }
    var remember = function (key, open) {
      saved[key] = open ? 1 : 0;
      try { localStorage.setItem("agent.sections", JSON.stringify(saved)); } catch (e) { /* ignored */ }
    };
    var bar = document.createElement("nav");
    bar.className = "tabs section-bar";
    groups.forEach(function (d) {
      var h2 = d.querySelector(":scope > summary h2");
      if (!h2) return;
      var name = (h2.firstChild && h2.firstChild.nodeType === 3 ? h2.firstChild.textContent : h2.textContent).trim();
      var key = h2.id || d.id || name;
      var bad = d.querySelectorAll(".badge.chk-failing, .badge.sev-critical").length;
      var warn = d.querySelectorAll(".badge.chk-warning, .badge.sev-warning").length;
      var link = document.createElement("a");
      link.href = "#";
      link.textContent = name;
      [[bad, "chk-failing"], [warn, "chk-warning"]].forEach(function (c) {
        if (!c[0]) return;
        var b = document.createElement("span");
        b.className = "badge " + c[1];
        b.textContent = c[0];
        h2.appendChild(b);
        link.appendChild(b.cloneNode(true));
      });
      d.open = bad || warn ? true : saved[key] === 1;
      d.querySelector(":scope > summary").addEventListener("click", function () { remember(key, !d.open); });
      link.addEventListener("click", function (e) {
        e.preventDefault();
        d.open = true;
        remember(key, true);
        d.scrollIntoView({ block: "start" });
      });
      d.dataset.key = key;
      bar.appendChild(link);
    });
    [[sections.dataset.expand, true], [sections.dataset.collapse, false]].forEach(function (b) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "link";
      btn.textContent = b[0];
      btn.addEventListener("click", function () {
        groups.forEach(function (d) { d.open = b[1]; if (d.dataset.key) remember(d.dataset.key, b[1]); });
      });
      bar.appendChild(btn);
    });
    sections.before(bar);
  }

  window.addEventListener("hashchange", openTarget);
  openTarget();

  // The selected agent's panel (rendered at the end of a possibly long list)
  // floats in front as a modal instead, so it stays visible regardless of
  // list length or scroll position. Closing it follows the panel's own
  // "chiudi" link, which keeps the list's filters/search.
  //
  // "Riduci" shrinks it to a bar, bottom left (the job dock is bottom
  // right), to work on the list behind it. Reduced agents stay there as a
  // row of bars, one per computer, while the list reloads and other agents
  // are opened: a click on a bar opens that agent again, its "×" drops it.
  // The row lives in the browser tab (sessionStorage) and shows on every
  // page, like the job dock; away from the list a bar goes back to the list
  // the agent was reduced from.
  var panel = document.querySelector("section.panel");
  var dock = document.getElementById("paneldock");
  var docked = [];
  function loadDock() {
    try { docked = JSON.parse(sessionStorage.getItem("panel.docked") || "[]"); } catch (e) { docked = []; }
    if (!Array.isArray(docked)) docked = [];
  }
  function saveDock() {
    try { sessionStorage.setItem("panel.docked", JSON.stringify(docked.slice(-12))); } catch (e) { /* ignored */ }
  }
  function isDocked(id) { return docked.some(function (d) { return d.id === id; }); }
  function undock(id) { docked = docked.filter(function (d) { return d.id !== id; }); saveDock(); }
  function dockAgent(id, name) { if (!isDocked(id)) docked.push({ id: id, name: name, url: agentURL(id) }); saveDock(); }
  function agentURL(id) {
    var u = new URL(location.href);
    u.searchParams.set("agent", id);
    u.searchParams.delete("tab");
    u.hash = "";
    return u.pathname + u.search;
  }
  if (dock) {
    loadDock();
    var current = panel ? panel.dataset.agent : "";
    var onList = !!document.querySelector("table.agents");
    var small = false;

    // drawDock lays out the bars of the reduced agents other than the one
    // in the panel; the panel itself, when reduced, is the last bar.
    var drawDock = function () {
      dock.querySelectorAll(".dockbar").forEach(function (b) { b.remove(); });
      docked.forEach(function (d) {
        if (d.id === current) return;
        var bar = document.createElement("div");
        bar.className = "dockbar";
        var a = document.createElement("a");
        a.href = onList ? agentURL(d.id) : (d.url || "/agents?agent=" + encodeURIComponent(d.id));
        a.textContent = d.name;
        a.title = dock.dataset.show;
        a.addEventListener("click", function () {
          // Opening another agent reduces the one in front to its bar.
          if (current && !small) dockAgent(current, panel.dataset.name);
          undock(d.id);
        });
        var x = document.createElement("button");
        x.type = "button";
        x.className = "link";
        x.textContent = "×";
        x.title = dock.dataset.close;
        x.addEventListener("click", function () { undock(d.id); drawDock(); });
        bar.append(a, x);
        if (panel) dock.insertBefore(bar, panel); else dock.appendChild(bar);
      });
      dock.hidden = !dock.children.length;
      // Leave the bars uncovered by the panel in front.
      document.body.classList.toggle("dock-bars", !!dock.querySelector(".dockbar"));
    };

    if (panel) {
      dock.appendChild(panel);
      var closeLink = panel.querySelector("a.panel-close");
      var backdrop = document.createElement("div");
      backdrop.className = "panel-backdrop";
      document.body.appendChild(backdrop);
      document.body.classList.add("panel-open");
      var closePanel = function () {
        undock(current);
        if (closeLink) location.href = closeLink.href;
      };
      if (closeLink) closeLink.addEventListener("click", function () { undock(current); });
      backdrop.addEventListener("click", closePanel);
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && !small) closePanel();
      });

      var toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "link panel-min";
      var setSmall = function (on) {
        small = on;
        document.body.classList.toggle("panel-small", on);
        toggle.textContent = on ? dock.dataset.show : dock.dataset.hide;
        if (on) dockAgent(current, panel.dataset.name); else undock(current);
      };
      toggle.addEventListener("click", function () { setSmall(!small); });
      var title = panel.querySelector("header h2");
      if (title) title.addEventListener("click", function () { if (small) setSmall(false); });
      if (closeLink) closeLink.before(toggle);
      setSmall(isDocked(current));
    }
    drawDock();
  }

  // Picking a script from the built-in library fills the textarea next to
  // it, which stays editable (the operator may still change it before the
  // approval); it is not resubmitted on its own (no "name").
  document.querySelectorAll("select.script-preset").forEach(function (sel) {
    sel.addEventListener("change", function () {
      if (!sel.value) return;
      var ta = sel.closest("form").querySelector('textarea[name="script"]');
      if (ta) ta.value = sel.value;
    });
  });

  // "Select all" boxes tick every agent box of their form.
  document.querySelectorAll("input[data-check-all]").forEach(function (all) {
    all.addEventListener("change", function () {
      all.form.querySelectorAll('input[type=checkbox][name="agent"]').forEach(function (c) { c.checked = all.checked; });
    });
  });

  // Shift+click ticks (or clears) a whole range of boxes, as in a file
  // manager: from the box clicked last to this one, among the boxes of the
  // same name in the same form (agents in a list, for example).
  var lastBox = null;
  document.addEventListener("click", function (e) {
    var box = e.target;
    if (!(box instanceof HTMLInputElement) || box.type !== "checkbox" || !box.name || box.hasAttribute("data-check-all")) return;
    if (e.shiftKey && lastBox && lastBox !== box && lastBox.name === box.name && lastBox.form === box.form && document.contains(lastBox)) {
      var scope = box.form || document;
      var boxes = Array.prototype.filter.call(scope.querySelectorAll('input[type=checkbox]'), function (c) {
        return c.name === box.name && c.form === box.form && !c.disabled;
      });
      var a = boxes.indexOf(lastBox), b = boxes.indexOf(box);
      if (a >= 0 && b >= 0) {
        boxes.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (c) {
          if (c.checked !== box.checked) {
            c.checked = box.checked;
            c.dispatchEvent(new Event("change", { bubbles: true }));
          }
        });
        // Shift+click also selects the text in between: not wanted here.
        if (window.getSelection) window.getSelection().removeAllRanges();
      }
    }
    lastBox = box;
  });

  // Theme, style and language apply as soon as they are chosen; the Apply buttons
  // stay for browsers without scripts.
  document.querySelectorAll("header form.theme, header form.lang").forEach(function (f) {
    var sels = f.querySelectorAll("select"), btn = f.querySelector("button");
    if (!sels.length || !btn) return;
    btn.hidden = true;
    sels.forEach(function (sel) { sel.addEventListener("change", function () { f.submit(); }); });
  });

  // Filter forms (class autosubmit) apply as soon as a choice changes.
  document.querySelectorAll("form.autosubmit").forEach(function (f) {
    var btn = f.querySelector("button");
    if (btn) btn.hidden = true;
    f.querySelectorAll("select").forEach(function (sel) {
      sel.addEventListener("change", function () { f.submit(); });
    });
  });

  // Navigation drop-downs: one open at a time, closed by a click elsewhere.
  var menus = document.querySelectorAll("nav details.menu");
  menus.forEach(function (d) {
    d.addEventListener("toggle", function () {
      if (d.open) menus.forEach(function (o) { if (o !== d) o.open = false; });
    });
  });
  document.addEventListener("click", function (e) {
    menus.forEach(function (d) { if (d.open && !d.contains(e.target)) d.open = false; });
  });

  // Help "?": one open at a time, closed by a click elsewhere or Escape.
  var helps = document.querySelectorAll("details.help");
  helps.forEach(function (d) {
    d.addEventListener("toggle", function () {
      if (d.open) helps.forEach(function (o) { if (o !== d) o.open = false; });
    });
  });
  document.addEventListener("click", function (e) {
    helps.forEach(function (d) { if (d.open && !d.contains(e.target)) d.open = false; });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") helps.forEach(function (d) { d.open = false; });
  });

  var tpl = document.getElementById("agent-menu");
  if (!tpl) return;
  var menu = null;

  function close() {
    if (menu) { menu.remove(); menu = null; }
  }

  // panelURL opens the agent in the bottom panel, keeping the list filters.
  function panelURL(id, tab, hash) {
    var u = new URL(location.href);
    u.searchParams.set("agent", id);
    if (tab) u.searchParams.set("tab", tab); else u.searchParams.delete("tab");
    u.hash = hash || "";
    return u.pathname + u.search + u.hash;
  }

  function post(action, fields) {
    var f = document.createElement("form");
    f.method = "post";
    f.action = action;
    fields.csrf = tpl.dataset.csrf;
    fields["return"] = location.pathname + location.search;
    Object.keys(fields).forEach(function (k) {
      var i = document.createElement("input");
      i.type = "hidden"; i.name = k; i.value = fields[k];
      f.appendChild(i);
    });
    document.body.appendChild(f);
    f.submit();
  }

  document.addEventListener("contextmenu", function (e) {
    var row = e.target.closest("tr[data-agent]");
    if (!row) return;
    e.preventDefault();
    close();
    var id = row.dataset.agent;
    menu = tpl.content.firstElementChild.cloneNode(true);
    menu.querySelector(".ctx-title").textContent = row.dataset.name || "";
    menu.querySelectorAll("[data-only-windows]").forEach(function (el) {
      if (row.dataset.os !== "windows") el.remove();
    });
    menu.querySelectorAll("[data-only-files]").forEach(function (el) {
      if (!row.hasAttribute("data-files")) el.remove();
    });
    menu.querySelectorAll("[data-only-screen]").forEach(function (el) {
      if (!row.hasAttribute("data-screen")) el.remove();
    });
    menu.querySelectorAll("[data-only-active]").forEach(function (el) {
      if (row.dataset.status !== "active") el.remove();
    });
    menu.querySelectorAll("a[data-page]").forEach(function (a) {
      a.href = "/agents/" + id;
    });
    menu.querySelectorAll("a[data-tab]").forEach(function (a) {
      a.href = panelURL(id, a.dataset.tab, a.dataset.hash);
    });
    menu.querySelectorAll("a[data-href]").forEach(function (a) {
      a.href = a.dataset.href.replace("{id}", encodeURIComponent(id));
    });
    menu.querySelectorAll("button[data-post]").forEach(function (b) {
      b.addEventListener("click", function () {
        var fields = {};
        if (b.dataset.module) { fields.module = b.dataset.module; fields.action = b.dataset.action; }
        post(b.dataset.post.replace("{id}", encodeURIComponent(id)), fields);
      });
    });
    document.body.appendChild(menu);
    var w = menu.offsetWidth, h = menu.offsetHeight;
    menu.style.left = Math.min(e.pageX, window.scrollX + document.documentElement.clientWidth - w - 8) + "px";
    menu.style.top = Math.min(e.pageY, window.scrollY + document.documentElement.clientHeight - h - 8) + "px";
    var first = menu.querySelector("a, button");
    if (first) first.focus();
  });
  document.addEventListener("click", function (e) {
    if (menu && !menu.contains(e.target)) close();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") close();
  });
  window.addEventListener("scroll", close, { passive: true });
})();

// Collapsible groups remember whether they were closed (per browser);
// data-keep-open (a filter of the group is active) keeps one open.
(function () {
  document.querySelectorAll("details[data-remember]").forEach(function (d) {
    var key = "open-rmm." + d.dataset.remember;
    try {
      if (localStorage.getItem(key) === "closed" && !d.hasAttribute("data-keep-open")) d.open = false;
    } catch (e) { /* storage unavailable: the default applies */ }
    d.addEventListener("toggle", function () {
      try { localStorage.setItem(key, d.open ? "open" : "closed"); } catch (e) { /* ignored */ }
    });
  });
})();

// The agents sidebar (sites/AD/groups tree) can be collapsed to free up
// width for the table; remembered per browser, like the groups above.
(function () {
  var tree = document.querySelector(".tree");
  var toggle = document.querySelector("[data-sidebar-toggle]");
  if (!tree || !toggle) return;
  var key = "open-rmm.agents.sidebar";
  try {
    if (localStorage.getItem(key) === "collapsed") tree.classList.add("collapsed");
  } catch (e) { /* storage unavailable: the default applies */ }
  toggle.addEventListener("click", function () {
    tree.classList.toggle("collapsed");
    try { localStorage.setItem(key, tree.classList.contains("collapsed") ? "collapsed" : "open"); } catch (e) { /* ignored */ }
  });
})();

// Agents list: drag the right edge of a column header to resize it; the
// widths are remembered per browser, a double click on the edge resets them.
(function () {
  var tables = document.querySelectorAll("table.agents");
  if (!tables.length) return;
  function key(t) { return "open-rmm.agents.cols." + t.tHead.rows[0].cells.length; }
  function apply(t, widths) {
    var cells = t.tHead.rows[0].cells, total = 0;
    for (var i = 0; i < cells.length; i++) {
      cells[i].style.width = widths[i] + "px";
      total += widths[i];
    }
    t.style.tableLayout = "fixed";
    t.style.width = total + "px";
    t.classList.add("resized");
  }
  function load(t) {
    try {
      var w = JSON.parse(localStorage.getItem(key(t)) || "null");
      if (Array.isArray(w) && w.length === t.tHead.rows[0].cells.length) return w;
    } catch (e) { /* storage unavailable or invalid: natural widths */ }
    return null;
  }
  tables.forEach(function (t) {
    if (!t.tHead) return;
    var saved = load(t);
    if (saved) apply(t, saved);
    Array.prototype.forEach.call(t.tHead.rows[0].cells, function (th, i) {
      var grip = document.createElement("span");
      grip.className = "col-grip";
      grip.setAttribute("aria-hidden", "true");
      grip.title = t.dataset.resizeTitle || "";
      th.appendChild(grip);
      grip.addEventListener("dblclick", function (ev) {
        ev.preventDefault();
        try { localStorage.removeItem(key(t)); } catch (e) { /* ignored */ }
        Array.prototype.forEach.call(t.tHead.rows[0].cells, function (c) { c.style.width = ""; });
        t.style.tableLayout = "";
        t.style.width = "";
        t.classList.remove("resized");
      });
      grip.addEventListener("pointerdown", function (ev) {
        ev.preventDefault();
        var cells = t.tHead.rows[0].cells, widths = [];
        for (var j = 0; j < cells.length; j++) widths.push(cells[j].getBoundingClientRect().width);
        apply(t, widths);
        var startX = ev.clientX, start = widths[i];
        grip.setPointerCapture(ev.pointerId);
        document.body.classList.add("resizing");
        function move(e) {
          widths[i] = Math.max(32, Math.round(start + e.clientX - startX));
          apply(t, widths);
        }
        function up() {
          grip.removeEventListener("pointermove", move);
          grip.removeEventListener("pointerup", up);
          grip.removeEventListener("pointercancel", up);
          document.body.classList.remove("resizing");
          try { localStorage.setItem(key(t), JSON.stringify(widths)); } catch (e) { /* ignored */ }
        }
        grip.addEventListener("pointermove", move);
        grip.addEventListener("pointerup", up);
        grip.addEventListener("pointercancel", up);
      });
    });
  });
})();

// Agents workspace: the scrolling list shows the selected agent.
(function () {
  var list = document.querySelector(".list.scroll");
  var row = list && list.querySelector("tr.current");
  if (row) list.scrollTop = Math.max(0, row.offsetTop - list.clientHeight / 3);
})();

// Job dock: the operator's jobs in progress and just finished, in a corner
// of every page (GET /jobs/active.json).
(function () {
  "use strict";
  // Polls every 4 s while a job runs, every 30 s otherwise, and not while
  // the tab is hidden.
  var dock = document.getElementById("jobdock");
  if (dock && window.fetch) {
    var store = function (k, v) {
      try { if (v === undefined) return sessionStorage.getItem(k); sessionStorage.setItem(k, v); } catch (e) { return null; }
    };
    var closed = {};
    (store("jobdock.closed") || "").split(",").forEach(function (id) { if (id) closed[id] = true; });
    var timer = null;
    var el = function (tag, cls, text) {
      var e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text !== undefined) e.textContent = text;
      return e;
    };
    var render = function (jobs) {
      jobs = jobs.filter(function (j) { return !(j.final && closed[j.id]); });
      dock.replaceChildren();
      if (!jobs.length) { dock.hidden = true; return false; }
      var running = jobs.some(function (j) { return !j.final; });
      var small = store("jobdock.small") === "1";
      var head = el("div", "jobdock-head");
      head.appendChild(el("strong", "", dock.dataset.title + " (" + jobs.length + ")"));
      var all = el("a", "small", dock.dataset.all);
      all.href = "/jobs";
      head.appendChild(all);
      var toggle = el("button", "link", small ? dock.dataset.show : dock.dataset.hide);
      toggle.type = "button";
      toggle.addEventListener("click", function () { store("jobdock.small", small ? "0" : "1"); poll(); });
      head.appendChild(toggle);
      if (!running) {
        var close = el("button", "link", dock.dataset.close);
        close.type = "button";
        close.addEventListener("click", function () {
          jobs.forEach(function (j) { closed[j.id] = true; });
          store("jobdock.closed", Object.keys(closed).slice(-100).join(","));
          dock.hidden = true;
        });
        head.appendChild(close);
      }
      dock.appendChild(head);
      if (!small) {
        var list = el("ul");
        jobs.forEach(function (j) {
          var li = el("li");
          var a = el("a", "", j.host || j.id.slice(0, 8));
          a.href = "/jobs/" + j.id;
          li.appendChild(a);
          li.appendChild(el("span", "muted small", " " + j.action + " "));
          li.appendChild(el("span", "badge " + j.state, j.label));
          if (!j.final && j.progress) {
            var bar = el("progress");
            bar.max = 100;
            bar.value = j.progress;
            li.appendChild(bar);
          }
          if (j.message) li.appendChild(el("div", "muted small", j.message));
          list.appendChild(li);
        });
        dock.appendChild(list);
      }
      dock.hidden = false;
      return running;
    };
    var poll = function () {
      clearTimeout(timer);
      if (document.hidden) return;
      fetch(dock.dataset.src, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (jobs) { timer = setTimeout(poll, render(jobs) ? 4000 : 30000); })
        .catch(function () { timer = setTimeout(poll, 30000); });
    };
    document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });
    poll();
  }
})();

// Workflow editor: adds, removes and moves steps and rules from the
// <template>s of the page, shows the fields of the chosen type, and keeps
// the steps' order fields in page order (the server sorts by them).
(function () {
  var form = document.querySelector("form[data-wf-editor]");
  if (!form) return;
  var steps = form.querySelector("[data-wf-steps]");
  var stepTpl = document.getElementById("wf-step-tpl");
  var ruleTpl = document.getElementById("wf-rule-tpl");
  var next = 1000; // indexes of new rows, past those of the server

  function box(el) { return el.closest("[data-wf-rule], [data-wf-step]"); }

  // Fields of a step or a rule (not of the rules inside a step).
  function showType(b) {
    var t = b.querySelector("[data-wf-type]").value;
    b.querySelectorAll("[data-for]").forEach(function (el) {
      if (box(el) === b) el.hidden = el.getAttribute("data-for").split(" ").indexOf(t) < 0;
    });
  }

  function fromTemplate(tpl, placeholder, value) {
    var div = document.createElement("div");
    div.innerHTML = tpl.innerHTML.split(placeholder).join(value);
    return div.firstElementChild;
  }

  function number() {
    Array.prototype.forEach.call(steps.children, function (s, i) {
      s.querySelector("[data-wf-num]").textContent = (i + 1) + ".";
      s.querySelector("[data-wf-order]").value = i;
    });
  }

  form.addEventListener("change", function (e) {
    if (e.target.matches("[data-wf-type]")) showType(box(e.target));
  });
  form.addEventListener("click", function (e) {
    var b = e.target.closest("button[type=button]");
    if (!b) return;
    var s = box(b);
    if (b.matches("[data-wf-add-step]")) {
      var n = fromTemplate(stepTpl, "__S__", String(next++));
      steps.appendChild(n);
      n.querySelector("select").focus();
    } else if (b.matches("[data-wf-add-rule]")) {
      var c = b.closest("[data-wf-conds]");
      c.querySelector("[data-wf-rules]").appendChild(fromTemplate(ruleTpl, "__P__", c.getAttribute("data-wf-conds") + ".r." + next++));
      var none = s && s.querySelector(".wf-when > summary .muted"); // "(none: …)" no longer true
      if (none) none.remove();
    } else if (b.matches("[data-wf-remove]")) {
      s.remove();
    } else if (b.matches("[data-wf-up]") && s.previousElementSibling) {
      steps.insertBefore(s, s.previousElementSibling);
    } else if (b.matches("[data-wf-down]") && s.nextElementSibling) {
      steps.insertBefore(s.nextElementSibling, s);
    }
    number();
  });
  number();
})();
