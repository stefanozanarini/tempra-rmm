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
    var shown = function () {
      remoteText.value = text;
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
    send({ t: "key", key: e.keyCode, down: true });
  });
  canvas.addEventListener("keyup", function (e) {
    e.preventDefault();
    if (swallowV && e.keyCode === 86) {
      swallowV = false;
      return;
    }
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
  document.getElementById("screen-remote-copy").addEventListener("click", function () {
    remoteText.select();
    var done = function () { clip.textContent = clip.dataset.copied; };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(remoteText.value).then(done, function () { document.execCommand("copy"); done(); });
    } else {
      document.execCommand("copy");
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
  document.getElementById("screen-close").addEventListener("click", function () { send({ t: "close" }); });
})();
