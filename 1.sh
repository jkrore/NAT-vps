// ==UserScript==
// @name         m3u8提取 + Safari/iOS剪贴板兜底 + VLC一键拉起 (性能优化版)
// @namespace    tianya_optimized
// @version      1.3
// @author       memopac / amufeng (Optimized by Assistant)
// @description  捕获m3u8链接，支持 Fetch/XHR，修复了原版 MutationObserver 导致的严重性能损耗问题。
// @license      MIT
// @match        *://*.haijiao.com/*
// @match        *://*/post/details*
// @grant        GM_addStyle
// @grant        GM_setClipboard
// @grant        unsafeWindow
// @run-at       document-start
// ==/UserScript==

(function () {
  'use strict';

  const uw = (typeof unsafeWindow !== 'undefined' && unsafeWindow) ? unsafeWindow : window;
  let capturedM3u8Url = '';
  let lastCaptureAt = 0;

  // 注入样式
  GM_addStyle(`
    #hj-extract-btn {
      position: fixed; bottom: 20px; right: 20px; width: 60px; height: 60px;
      border-radius: 50%; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
      color: white; border: none; cursor: pointer; z-index: 999999; font-size: 24px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.3); transition: all 0.25s ease;
      user-select: none; -webkit-user-select: none;
    }
    #hj-extract-btn:hover { transform: scale(1.08); box-shadow: 0 6px 20px rgba(0,0,0,0.4); }
    #hj-extract-btn.success { background: linear-gradient(135deg, #4CAF50, #45a049); }
    #hj-extract-btn.error { background: linear-gradient(135deg, #f44336, #d32f2f); }
    #hj-toast {
      position: fixed; bottom: 100px; right: 16px; background: rgba(0,0,0,0.86);
      color: white; padding: 12px 14px; border-radius: 10px; z-index: 999999;
      font-size: 14px; max-width: min(360px, calc(100vw - 32px)); word-break: break-all;
      display: none; line-height: 1.45;
    }
    #hj-toast small { opacity: .82; display: block; margin-top: 6px; }
  `);

  // UI 控制逻辑
  function showToast(html, duration = 3500) {
    let toast = document.getElementById('hj-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'hj-toast';
      document.body.appendChild(toast);
    }
    toast.innerHTML = html;
    toast.style.display = 'block';
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => { toast.style.display = 'none'; }, duration);
  }

  function updateButtonState(state) {
    const btn = document.getElementById('hj-extract-btn');
    if (!btn) return;
    btn.className = state ? state : '';
    btn.textContent = state === 'success' ? '✓' : (state === 'error' ? '✗' : '📋');
  }

  function setCaptured(url) {
    if (!url) return;
    capturedM3u8Url = url;
    lastCaptureAt = Date.now();
    updateButtonState('success');
  }

  // 重置状态逻辑（用于页面跳转时）
  function resetState() {
    capturedM3u8Url = '';
    updateButtonState('');
  }

  // 剪贴板与 VLC 逻辑 (保留 46 楼优秀逻辑)
  function copyToClipboardSyncFirst(text) {
    let syncOk = false;
    try {
      if (typeof GM_setClipboard === 'function') {
        GM_setClipboard(text, 'text/plain');
        syncOk = true;
      }
    } catch (e) {}

    const asyncTry = (async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch (e) {}
      try {
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;';
        document.body.appendChild(ta); ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (ok) return true;
      } catch (e) {}
      return false;
    })();
    return { syncOk, asyncTry };
  }

  function openVLCInIOSFriendlyWay(url) {
    if (!url) return;
    const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
    const schemes = isIOS
      ? [`vlc-x-callback://x-callback-url/stream?url=${encodeURIComponent(url)}`, `vlc://${encodeURIComponent(url)}`]
      : [`vlc://open?url=${encodeURIComponent(url)}`, `vlc://${encodeURIComponent(url)}`];

    const tryOpen = (scheme) => {
      const a = document.createElement('a');
      a.href = scheme; a.style.display = 'none';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    };
    tryOpen(schemes[0]);
    setTimeout(() => tryOpen(schemes[1]), 350);
  }

  // m3u8 与解密逻辑
  const getRealVideoSrc = (content, requestUrl) => {
    try {
      if (!content) return "";
      if (content.includes("#EXTM3U")) {
        const baseUrl = requestUrl.substring(0, requestUrl.lastIndexOf('/') + 1);
        const filenameMatch = content.match(/([\w_]+_?)[\d]+\.ts/);
        if (filenameMatch) return baseUrl + filenameMatch[1] + ".m3u8";
      } else {
        const ts_path = content.split("\n")[6] || '';
        const reg = ts_path.match(/([\w_]+_?)[\d]+\.ts/);
        if (reg) return ts_path.replace(reg[0], reg[1] + ".m3u8");
      }
    } catch (e) {}
    return "";
  };

  const decodeEncryptString = (text) => {
    try {
      if (typeof text === 'string') {
        const tmp = JSON.parse(text);
        if (typeof tmp?.data === 'object') return tmp.data;
        if (typeof tmp?.data === 'string') return JSON.parse(atob(atob(atob(tmp.data))));
      }
    } catch (e) {}
    return text;
  };

  // Hook XHR
  (function hookXHR() {
    const OriginalXHR = uw.XMLHttpRequest;
    if (!OriginalXHR) return;
    uw.XMLHttpRequest = function () {
      const xhr = new OriginalXHR();
      let requestUrl = '';
      xhr.open = function (method, url) { requestUrl = url; return OriginalXHR.prototype.open.apply(this, arguments); };
      xhr.send = function () {
        xhr.addEventListener('load', async function () {
          try {
            if (requestUrl.includes("/api/address/")) {
              setCaptured(getRealVideoSrc(xhr.responseText, requestUrl));
            } else if (/\/api\/topic\/\d+/.test(requestUrl)) {
              const data = decodeEncryptString(xhr.responseText);
              if (data?.attachments) {
                data.attachments.forEach(async (el) => {
                  if (el.category === "video" && el.remoteUrl) {
                    try {
                      const res = await fetch(el.remoteUrl);
                      setCaptured(getRealVideoSrc(await res.text(), el.remoteUrl));
                    } catch (e) {}
                  }
                });
              }
            }
          } catch (e) {}
        });
        return OriginalXHR.prototype.send.apply(this, arguments);
      };
      return xhr;
    };
  })();

  // Hook Fetch
  (function hookFetch() {
    const originalFetch = uw.fetch;
    if (typeof originalFetch !== 'function') return;
    uw.fetch = async function () {
      const args = arguments;
      const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
      const resp = await originalFetch.apply(this, args);
      try {
        if (url.includes('/api/address/') || /\/api\/topic\/\d+/.test(url)) {
          const clone = resp.clone();
          const text = await clone.text();
          if (url.includes('/api/address/')) setCaptured(getRealVideoSrc(text, url));
          if (/\/api\/topic\/\d+/.test(url)) {
            const data = decodeEncryptString(text);
            if (data?.attachments) {
              data.attachments.forEach(async (el) => {
                if (el.category === "video" && el.remoteUrl) {
                  try {
                    const r2 = await originalFetch(el.remoteUrl);
                    setCaptured(getRealVideoSrc(await r2.text(), el.remoteUrl));
                  } catch (e) {}
                }
              });
            }
          }
        }
      } catch (e) {}
      return resp;
    };
  })();

  // 创建按钮
  function createButton() {
    if (document.getElementById('hj-extract-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'hj-extract-btn'; btn.textContent = '📋';
    btn.title = '点击：复制m3u8并尝试VLC播放（Shift+点击：只复制）';

    btn.addEventListener('click', (e) => {
      if (!capturedM3u8Url) {
        updateButtonState('error'); showToast('❌ 未检测到视频链接，请先播放视频触发请求');
        setTimeout(() => updateButtonState(''), 1200); return;
      }
      const onlyCopy = e.shiftKey;
      const { syncOk, asyncTry } = copyToClipboardSyncFirst(capturedM3u8Url);
      if (!onlyCopy) openVLCInIOSFriendlyWay(capturedM3u8Url);

      asyncTry.then((ok) => {
        if (syncOk || ok) {
          updateButtonState('success');
          showToast(`✅ 已复制${onlyCopy ? '' : '，并已尝试唤起 VLC'}：<br>${capturedM3u8Url}`, 4500);
        } else {
          updateButtonState('error');
          showToast(`⚠️ 自动复制失败，请在弹窗中手动复制。`, 3200);
          setTimeout(() => window.prompt('请长按全选并复制：', capturedM3u8Url), 80);
        }
        setTimeout(() => updateButtonState(''), 1200);
      });
    });
    document.body.appendChild(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createButton);
  } else {
    createButton();
  }

  // 【性能优化核心】使用 History API 替代 MutationObserver 监听路由变化
  uw.addEventListener('popstate', resetState);
  const originalPushState = uw.history.pushState;
  uw.history.pushState = function() {
      resetState();
      return originalPushState.apply(this, arguments);
  };
  const originalReplaceState = uw.history.replaceState;
  uw.history.replaceState = function() {
      resetState();
      return originalReplaceState.apply(this, arguments);
  };

})();
