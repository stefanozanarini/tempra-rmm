// Tempra RMM remote control: a <canvas> connected to the session over a
// WebSocket. Screen frames arrive as binary messages carrying the
// internal/screensession wire format (decoded here); input events are
// sent as small JSON messages, which the server turns into that same
// wire format before relaying them to the agent.
(function () {
  "use strict";
  var canvas = document.getElementById("screen-canvas");
  var status = document.getElementById("screen-status");
  var desk = document.getElementById("screen-desktop");
  var ctx = canvas.getContext("2d");
  var buf = new Uint8Array(0);
  var scale = 1; // canvas device pixels per remote virtual-desktop pixel
  var clip = document.getElementById("screen-clip");
  var pasteBtn = document.getElementById("screen-paste");
  var pasteBox = document.getElementById("screen-paste-box");
  var pasteText = document.getElementById("screen-paste-text");
  var remoteBox = document.getElementById("screen-remote-box");
  var remoteText = document.getElementById("screen-remote-text");
  var remoteFull = ""; // the whole text: the box shows its first line
  // shared: the agent shares the clipboard (its 'P' frame said so, and the
  // console marked the agent version as able to): only then are pasted
  // texts sent, as older helpers cannot decode them.
  var shared = false;
  var maxClip = 128 * 1024; // internal/screensession.MaxClipboardSize
  var monitorSel = document.getElementById("screen-monitor");
  // Drawing happens in arrival order: images decode asynchronously, and a
  // part of the screen must never be painted over by an older one.
  var drawing = Promise.resolve();
  function queue(fn) {
    drawing = drawing.then(fn).catch(function () {});
  }

  function append(chunk) {
    var next = new Uint8Array(buf.length + chunk.length);
    next.set(buf);
    next.set(chunk, buf.length);
    buf = next;
  }

  // Decodes as many complete frames as buf currently holds; mirrors
  // internal/screensession.Decoder.Feed.
  function drain() {
    while (buf.length > 0) {
      var kind = buf[0];
      if (kind === 0x46 /* 'F' */) {
        if (buf.length < 5) return;
        var n = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0, false);
        if (buf.length < 5 + n) return;
        showImage(buf.slice(5, 5 + n));
        buf = buf.slice(5 + n);
        continue;
      }
      if (kind === 0x54 /* 'T' */) {
        if (buf.length < 13) return;
        var th = new DataView(buf.buffer, buf.byteOffset + 1, 12);
        var tn = th.getUint32(8, false);
        if (buf.length < 13 + tn) return;
        showTile(th.getUint32(0, false), th.getUint32(4, false), buf.slice(13, 13 + tn));
        buf = buf.slice(13 + tn);
        continue;
      }
      if (kind === 0x4c /* 'L' */) {
        if (buf.length < 2) return;
        var count = buf[1];
        if (buf.length < 2 + 16 * count) return;
        var mons = [];
        var lv = new DataView(buf.buffer, buf.byteOffset + 2, 16 * count);
        for (var i = 0; i < count; i++) {
          mons.push({ w: lv.getInt32(16 * i + 8, false), h: lv.getInt32(16 * i + 12, false) });
        }
        setMonitors(mons);
        buf = buf.slice(2 + 16 * count);
        continue;
      }
      if (kind === 0x53 /* 'S' */) {
        if (buf.length < 9) return;
        var dv = new DataView(buf.buffer, buf.byteOffset + 1, 8);
        resize(dv.getUint32(0, false), dv.getUint32(4, false));
        buf = buf.slice(9);
        continue;
      }
      if (kind === 0x43 /* 'C' */) {
        if (buf.length < 5) return;
        var cn = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0, false);
        if (buf.length < 5 + cn) return;
        remoteCopied(new TextDecoder().decode(buf.slice(5, 5 + cn)));
        buf = buf.slice(5 + cn);
        continue;
      }
      if (kind === 0x50 /* 'P' */) {
        if (buf.length < 2) return;
        setShared(buf[1] === 1);
        buf = buf.slice(2);
        continue;
      }
      if (kind === 0x5a /* 'Z' */) {
        if (buf.length < 5) return;
        var zn = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0, false);
        if (buf.length < 5 + zn) return;
        if (zn > 0) fileFrame(buf[5], buf.slice(6, 5 + zn));
        buf = buf.slice(5 + zn);
        continue;
      }
      if (kind === 0x44 /* 'D' */) {
        if (buf.length < 2) return;
        desk.textContent = desk.dataset["d" + buf[1]] || "";
        buf = buf.slice(2);
        continue;
      }
      // Unknown kind: drop everything, the stream cannot be resynchronized.
      buf = new Uint8Array(0);
      return;
    }
  }

  function setShared(on) {
    if (!canvas.dataset.v2) return;
    shared = on;
    pasteBtn.hidden = !on;
    if (!on) clip.textContent = clip.dataset.off;
  }

  // Text copied on the remote computer: straight to the operator's
  // clipboard where the browser allows it, otherwise shown to copy by hand.
  function remoteCopied(text) {
    // Only whitespace (some programs clear the clipboard so): nothing to show.
    if (!text.trim()) return;
    var shown = function () {
      remoteFull = text;
      // The first line with text in it, "…" when there is more.
      var lines = text.split(/\r?\n/).filter(function (l) { return l.trim(); });
      remoteText.value = lines[0].trim() + (lines.length > 1 ? " …" : "");
      remoteText.title = text.length > 2000 ? text.slice(0, 2000) + " …" : text;
      remoteBox.hidden = false;
    };
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      shown();
      return;
    }
    navigator.clipboard.writeText(text).then(function () {
      clip.textContent = clip.dataset.copied;
    }, shown);
  }

  // Sends text to the remote clipboard, then Ctrl+V; wrapCtrl presses Ctrl
  // too, when the operator is not already holding it.
  function pasteRemote(text, wrapCtrl) {
    if (new TextEncoder().encode(text).length > maxClip) {
      clip.textContent = clip.dataset.large;
      return;
    }
    send({ t: "clip", text: text });
    sendCtrlV(wrapCtrl);
    clip.textContent = clip.dataset.sent;
  }

  function sendCtrlV(wrapCtrl) {
    if (wrapCtrl) send({ t: "key", key: 17, down: true });
    send({ t: "key", key: 86, down: true });
    send({ t: "key", key: 86, down: false });
    if (wrapCtrl) send({ t: "key", key: 17, down: false });
  }

  function resize(w, h) {
    queue(function () {
      canvas.width = w;
      canvas.height = h;
    });
  }

  // A whole frame (agents before 1.2.4), scaled to the canvas.
  function showImage(jpegBytes) {
    var decoded = createImageBitmap(new Blob([jpegBytes], { type: "image/jpeg" }));
    queue(function () {
      return decoded.then(function (bmp) {
        if (canvas.width && canvas.height) ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
        bmp.close();
      });
    });
  }

  // A changed part of the screen, at its place.
  function showTile(x, y, jpegBytes) {
    var decoded = createImageBitmap(new Blob([jpegBytes], { type: "image/jpeg" }));
    queue(function () {
      return decoded.then(function (bmp) {
        ctx.drawImage(bmp, x, y);
        bmp.close();
      });
    });
  }

  // The monitor menu: shown with two monitors or more.
  function setMonitors(mons) {
    if (!canvas.dataset.v2) return;
    var current = monitorSel.value || "-1";
    monitorSel.textContent = "";
    var all = document.createElement("option");
    all.value = "-1";
    all.textContent = monitorSel.dataset.all;
    monitorSel.appendChild(all);
    mons.forEach(function (m, i) {
      var o = document.createElement("option");
      o.value = String(i);
      o.textContent = monitorSel.dataset.one.replace("%d", i + 1) + (i === 0 ? " (" + monitorSel.dataset.primary + ")" : "") + " · " + m.w + "×" + m.h;
      monitorSel.appendChild(o);
    });
    monitorSel.value = Number(current) < mons.length ? current : "-1";
    monitorSel.hidden = mons.length < 2;
  }

  // wss:// whenever the page itself is https:, which it always is outside
  // local development: this already matches the page's own scheme.
  var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + canvas.dataset.ws); // nosemgrep: detect-insecure-websocket
  ws.binaryType = "arraybuffer";
  function send(m) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
  }
  // The status says "connected" only once the server reports that the
  // agent has joined: the WebSocket alone reaches just the console.
  ws.onmessage = function (e) {
    if (typeof e.data === "string") {
      status.textContent = e.data;
      return;
    }
    append(new Uint8Array(e.data));
    drain();
  };
  ws.onclose = function () {
    if (status.textContent === canvas.dataset.connected) status.textContent = canvas.dataset.closed;
  };

  function toRemote(e) {
    var r = canvas.getBoundingClientRect();
    var sx = canvas.width / r.width, sy = canvas.height / r.height;
    return { x: Math.round((e.clientX - r.left) * sx), y: Math.round((e.clientY - r.top) * sy) };
  }
  canvas.addEventListener("contextmenu", function (e) { e.preventDefault(); });
  canvas.addEventListener("mousemove", function (e) {
    var p = toRemote(e);
    send({ t: "move", x: p.x, y: p.y });
  });
  canvas.addEventListener("mousedown", function (e) { canvas.focus(); send({ t: "button", button: e.button, down: true }); });
  canvas.addEventListener("mouseup", function (e) { send({ t: "button", button: e.button, down: false }); });
  canvas.addEventListener("wheel", function (e) {
    e.preventDefault();
    send({ t: "wheel", delta: Math.round(-e.deltaY) });
  }, { passive: false });
  // keyCode is deprecated but, for letters, digits and the common
  // control keys, its values are the same as Windows virtual-key codes
  // (both trace back to the same legacy scheme): good enough to drive
  // SendInput without a full per-layout mapping table.
  //
  // Ctrl+V (Cmd+V on a Mac) with a shared clipboard is left to the
  // browser, whose paste event carries the operator's text: it goes to the
  // remote clipboard first, then the remote Ctrl+V. Without a paste event
  // (no text, or a browser that sends none), V alone goes on after a moment
  // and pastes whatever the remote clipboard holds.
  var pending = null; // the Ctrl+V awaiting its paste event
  var swallowV = false; // the V's keyup, already sent with the paste
  // From agent 1.2.5 the characters typed go as characters, not keys: the
  // remote computer types what the operator's keyboard produced, whatever
  // the two layouts (accented letters, AltGr symbols, a Mac keyboard).
  // Shortcuts (with Ctrl, Alt or Cmd) and the other keys still go as keys.
  var typed = {}; // keys whose keydown went as a character: no keyup
  function typedChar(e) {
    if (!canvas.dataset.v3 || e.isComposing || Array.from(e.key).length !== 1) return "";
    var altGr = e.getModifierState && e.getModifierState("AltGraph");
    if (!altGr && (e.ctrlKey || e.altKey || e.metaKey)) return "";
    return e.key;
  }
  canvas.addEventListener("keydown", function (e) {
    if (shared && e.keyCode === 86 && (e.ctrlKey || e.metaKey) && !e.altKey) {
      if (pending) return;
      swallowV = true;
      var p = { wrapCtrl: !e.ctrlKey };
      p.timer = setTimeout(function () {
        if (pending !== p) return;
        pending = null;
        sendCtrlV(p.wrapCtrl);
      }, 500);
      pending = p;
      return;
    }
    e.preventDefault();
    var ch = typedChar(e);
    if (ch) {
      // AltGr arrives as Ctrl+Alt, already pressed remotely: released
      // first, or the character would turn into a shortcut.
      if (e.ctrlKey) send({ t: "key", key: 17, down: false });
      if (e.altKey) send({ t: "key", key: 18, down: false });
      typed[e.code] = true;
      send({ t: "char", char: ch });
      return;
    }
    if (e.key === "Dead") return; // the accent comes with the next key
    send({ t: "key", key: e.keyCode, down: true });
  });
  canvas.addEventListener("keyup", function (e) {
    e.preventDefault();
    if (swallowV && e.keyCode === 86) {
      swallowV = false;
      return;
    }
    if (typed[e.code]) {
      delete typed[e.code];
      return;
    }
    if (e.key === "Dead") return;
    send({ t: "key", key: e.keyCode, down: false });
  });
  document.addEventListener("paste", function (e) {
    if (!pending) return;
    var p = pending;
    pending = null;
    clearTimeout(p.timer);
    e.preventDefault();
    var text = e.clipboardData ? e.clipboardData.getData("text/plain") : "";
    if (text) {
      pasteRemote(text, p.wrapCtrl);
      return;
    }
    sendCtrlV(p.wrapCtrl);
  });
  pasteBtn.addEventListener("click", function () {
    pasteBox.hidden = false;
    pasteText.focus();
  });
  document.getElementById("screen-paste-send").addEventListener("click", function () {
    pasteRemote(pasteText.value, true);
    pasteText.value = "";
    pasteBox.hidden = true;
    canvas.focus();
  });
  document.getElementById("screen-paste-cancel").addEventListener("click", function () {
    pasteText.value = "";
    pasteBox.hidden = true;
    canvas.focus();
  });
  // Without the Clipboard API, the whole text is copied from a scratch
  // field: the box shows only its first line.
  function copyByHand(text) {
    var t = document.createElement("textarea");
    t.value = text;
    t.setAttribute("readonly", "");
    t.style.position = "fixed";
    t.style.opacity = "0";
    document.body.appendChild(t);
    t.select();
    document.execCommand("copy");
    document.body.removeChild(t);
  }
  document.getElementById("screen-remote-copy").addEventListener("click", function () {
    var done = function () {
      clip.textContent = clip.dataset.copied;
      remoteBox.hidden = true;
      canvas.focus();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(remoteFull).then(done, function () { copyByHand(remoteFull); done(); });
    } else {
      copyByHand(remoteFull);
      done();
    }
  });
  document.getElementById("screen-remote-hide").addEventListener("click", function () {
    remoteBox.hidden = true;
    canvas.focus();
  });
  monitorSel.addEventListener("change", function () {
    send({ t: "monitor", monitor: Number(monitorSel.value) });
    canvas.focus();
  });
  document.getElementById("screen-sas").addEventListener("click", function () { send({ t: "sas" }); canvas.focus(); });
  // Closing the session also closes the tab. Browsers let a page close
  // only a tab a script opened, so otherwise it goes back to the agent.
  document.getElementById("screen-close").addEventListener("click", function () {
    send({ t: "close" });
    var left = false;
    var leave = function () {
      if (left) return;
      left = true;
      window.close();
      setTimeout(function () { location.href = document.getElementById("screen-back").href; }, 300);
    };
    if (ws.readyState !== WebSocket.OPEN) {
      leave();
      return;
    }
    // Leave once the server has closed the session, or soon anyway.
    ws.addEventListener("close", leave);
    setTimeout(leave, 2000);
  });
  // Shortcuts the browser or the operator's own system would take.
  var keysSel = document.getElementById("screen-keys");
  keysSel.addEventListener("change", function () {
    var keys = keysSel.value ? keysSel.value.split(",").map(Number) : [];
    keys.forEach(function (k) { send({ t: "key", key: k, down: true }); });
    keys.slice().reverse().forEach(function (k) { send({ t: "key", key: k, down: false }); });
    keysSel.value = "";
    canvas.focus();
  });

  // Full screen. Where the browser allows it (Chrome, Edge), the keyboard
  // is locked too: Win, Alt+Tab and the like go to the remote computer, and
  // Esc must be held to leave.
  var wrap = document.getElementById("screen-wrap");
  var fullBtn = document.getElementById("screen-full");
  fullBtn.addEventListener("click", function () {
    if (document.fullscreenElement) {
      document.exitFullscreen();
      return;
    }
    wrap.requestFullscreen().then(function () {
      if (navigator.keyboard && navigator.keyboard.lock) navigator.keyboard.lock().catch(function () {});
      canvas.focus();
    }, function () {});
  });
  document.addEventListener("fullscreenchange", function () {
    var on = document.fullscreenElement === wrap;
    fullBtn.textContent = on ? fullBtn.dataset.off : fullBtn.dataset.on;
    if (!on && navigator.keyboard && navigator.keyboard.unlock) navigator.keyboard.unlock();
  });

  // File transfers (agent 1.2.5): one at a time each way, through the
  // session itself. Files sent land on the Desktop of the user signed in
  // at the console; files fetched are downloaded by the browser.
  var filesBox = document.getElementById("screen-files-box");
  var fileStatus = document.getElementById("screen-file-status");
  var fileCancel = document.getElementById("screen-file-cancel");
  var putting = null; // { name, cancelled }: null again once answered or cancelled
  var getting = null; // { name, size, got, parts, cancelled }
  function fmt(key, a, b) {
    var t = fileStatus.dataset[key] || key;
    return t.replace("%s", a === undefined ? "" : a).replace("%d", b === undefined ? "" : b).replace("%%", "%");
  }
  function fileSay(text) {
    filesBox.hidden = false;
    fileStatus.textContent = text;
    fileCancel.hidden = !putting && !getting;
  }
  function failText(r) {
    if (r.code && fileStatus.dataset[r.code]) return fileStatus.dataset[r.code];
    return fmt("failed", r.error || "");
  }
  function toBase64(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    return btoa(s);
  }
  function sendFile(file) {
    if (!canvas.dataset.v3 || ws.readyState !== WebSocket.OPEN) return;
    if (putting) {
      fileSay(fmt("busy"));
      return;
    }
    var p = { name: file.name, cancelled: false };
    putting = p;
    send({ t: "fileput", name: file.name, size: file.size });
    var chunk = 48 * 1024, off = 0;
    var next = function () {
      // Stopped by Cancel or by the agent's answer (an error).
      if (putting !== p || ws.readyState !== WebSocket.OPEN) return;
      // Not faster than the connection: the screen shares it.
      if (ws.bufferedAmount > 1024 * 1024) {
        setTimeout(next, 50);
        return;
      }
      if (off >= file.size) {
        send({ t: "fileend" });
        return;
      }
      file.slice(off, off + chunk).arrayBuffer().then(function (ab) {
        if (putting !== p) return;
        send({ t: "filedata", data: toBase64(new Uint8Array(ab)) });
        off += ab.byteLength;
        fileSay(fmt("sending", p.name, Math.floor((100 * off) / Math.max(file.size, 1))));
        next();
      }, function () {
        if (putting !== p) return;
        putting = null;
        send({ t: "filecancel" });
        fileSay(fmt("failed", file.name));
      });
    };
    fileSay(fmt("sending", p.name, 0));
    next();
  }
  // The remote file browser (agent 1.2.6): folders open in place, a file
  // is fetched on click.
  var browser = document.getElementById("screen-browser");
  var browserNote = document.getElementById("screen-browser-note");
  var browserPath = document.getElementById("screen-browser-path");
  var browserRows = document.getElementById("screen-browser-rows");
  var browserUp = document.getElementById("screen-browser-up");
  var fetchPicked = null;
  var listed = null; // the listing shown
  function listFolder(path) {
    if (!browser || ws.readyState !== WebSocket.OPEN) return;
    browserNote.textContent = "…";
    send({ t: "filelist", path: path });
  }
  function joinPath(dir, name) {
    var sep = /^[A-Za-z]:/.test(dir) || dir.indexOf("\\") >= 0 ? "\\" : "/";
    return dir.charAt(dir.length - 1) === sep ? dir + name : dir + sep + name;
  }
  function humanSize(n) {
    var units = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + units[i];
  }
  function browserRow(label, sub, onClick, size, modified) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    var a = document.createElement("a");
    a.textContent = label;
    a.addEventListener("click", onClick);
    td.appendChild(a);
    if (sub) {
      var m = document.createElement("span");
      m.className = "muted small";
      m.textContent = " " + sub;
      td.appendChild(m);
    }
    tr.appendChild(td);
    [size || "", modified || ""].forEach(function (v) {
      var c = document.createElement("td");
      c.className = "muted";
      c.textContent = v;
      tr.appendChild(c);
    });
    browserRows.appendChild(tr);
  }
  function showListing(l) {
    if (!browser) return;
    listed = l;
    browserRows.textContent = "";
    browserPath.textContent = l.path || browser.dataset.places;
    browserUp.disabled = !l.path;
    browserNote.textContent = "";
    (l.places || []).forEach(function (p) {
      browserRow("📁 " + p.name, p.name === p.path ? "" : p.path, function () { listFolder(p.path); });
    });
    (l.entries || []).forEach(function (e) {
      var full = joinPath(l.path, e.name);
      var when = e.modified ? new Date(e.modified).toLocaleString() : "";
      if (e.dir) {
        browserRow("📁 " + e.name, "", function () { listFolder(full); }, "", when);
      } else {
        browserRow("📄 " + e.name, "", function () { if (fetchPicked) fetchPicked(full); }, humanSize(e.size || 0), when);
      }
    });
    if (l.path && !(l.entries || []).length) browserNote.textContent = browser.dataset.empty;
    if (l.truncated) browserNote.textContent = browser.dataset.truncated.replace("%d", (l.entries || []).length);
  }
  if (browser) {
    document.getElementById("screen-file-browse").addEventListener("click", function () {
      browser.hidden = !browser.hidden;
      if (!browser.hidden && !listed) listFolder("");
    });
    browserUp.addEventListener("click", function () { if (listed && listed.path) listFolder(listed.parent || ""); });
    document.getElementById("screen-browser-home").addEventListener("click", function () { listFolder(""); });
  }

  function fileFrame(op, data) {
    var json = function () {
      try { return JSON.parse(new TextDecoder().decode(data)); } catch (e) { return {}; }
    };
    if (op === 11 /* FileListing */) {
      showListing(json());
      return;
    }
    if (op === 8 /* FileResult */) {
      var r = json();
      if (r.op === "list") {
        if (browserNote) browserNote.textContent = failText(r);
        return;
      }
      if (r.op === "put" && putting) {
        var cancelled = putting.cancelled;
        putting = null;
        if (!cancelled) fileSay(r.ok ? fmt("sent", r.path) : failText(r));
      } else if (r.op === "get" && getting) {
        var gc = getting.cancelled;
        getting = null;
        if (!gc) fileSay(failText(r));
      }
      return;
    }
    if (!getting || getting.cancelled) return;
    if (op === 5 /* FileGetBegin */) {
      var h = json();
      getting.name = h.name || "file";
      getting.size = h.size || 0;
      fileSay(fmt("receiving", getting.name, 0));
    } else if (op === 6 /* FileGetData */) {
      getting.parts.push(data);
      getting.got += data.length;
      fileSay(fmt("receiving", getting.name, Math.floor((100 * getting.got) / Math.max(getting.size, 1))));
    } else if (op === 7 /* FileGetEnd */) {
      var g = getting;
      getting = null;
      var a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob(g.parts));
      a.download = g.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 60000);
      fileSay(fmt("received", g.name));
    }
  }
  if (filesBox) {
    var pick = document.getElementById("screen-file-pick");
    var pathIn = document.getElementById("screen-file-path");
    document.getElementById("screen-files").addEventListener("click", function () {
      filesBox.hidden = !filesBox.hidden;
    });
    document.getElementById("screen-files-hide").addEventListener("click", function () {
      filesBox.hidden = true;
      canvas.focus();
    });
    document.getElementById("screen-file-send").addEventListener("click", function () { pick.click(); });
    pick.addEventListener("change", function () {
      if (pick.files.length) sendFile(pick.files[0]);
      pick.value = "";
    });
    var fetchFile = function (picked) {
      var path = typeof picked === "string" ? picked : pathIn.value.trim();
      if (!path || ws.readyState !== WebSocket.OPEN) return;
      if (getting) {
        fileSay(fmt("busy"));
        return;
      }
      getting = { name: path, size: 0, got: 0, parts: [], cancelled: false };
      send({ t: "fileget", path: path });
      fileSay(fmt("receiving", path, 0));
    };
    document.getElementById("screen-file-get").addEventListener("click", function () { fetchFile(); });
    fetchPicked = fetchFile;
    pathIn.addEventListener("keydown", function (e) {
      if (e.key === "Enter") fetchFile();
    });
    fileCancel.addEventListener("click", function () {
      if (putting) putting.cancelled = true;
      if (getting) getting.cancelled = true;
      putting = null;
      getting = null;
      send({ t: "filecancel" });
      fileSay(fmt("cancelled"));
    });
    canvas.addEventListener("dragover", function (e) {
      if (!e.dataTransfer || Array.prototype.indexOf.call(e.dataTransfer.types, "Files") < 0) return;
      e.preventDefault();
      canvas.classList.add("dropping");
    });
    canvas.addEventListener("dragleave", function () { canvas.classList.remove("dropping"); });
    canvas.addEventListener("drop", function (e) {
      e.preventDefault();
      canvas.classList.remove("dropping");
      if (e.dataTransfer && e.dataTransfer.files.length) sendFile(e.dataTransfer.files[0]);
    });
  }
})();
