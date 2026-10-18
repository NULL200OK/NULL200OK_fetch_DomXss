# NULL200OK_fetch_DomXss

**Runtime DOM-based XSS, Trusted Types, DOMPurify & prototype pollution detector for modern browsers.**

A Manifest V3 extension that instruments the browser at three layers — page hooks, an isolated content script, and a central Service Worker taint engine — to detect client-side data-flow vulnerabilities as they happen.

---

## 📥 Installation (How to install the extension)

### Option A: Direct Download (Recommended for Users)
You don't need to write any code or use the terminal to use the extension.

1. Go to the **Actions** tab in this repository.
2. Click on the latest successful workflow run (e.g., `Build NULL200OK_fetch_DomXss`).
3. Scroll down to the **Artifacts** section at the bottom of the page.
4. Download the file named **`NULL200OK_fetch_DomXss-build.zip`**.
5. Unzip the downloaded file. You will find a folder named **`dist`**.
6. Open your Chromium browser (Chrome, Edge, Brave, or Opera) and go to `chrome://extensions`.
7. Enable **Developer mode** (toggle in the top-right corner).
8. Click **Load unpacked** and select the **`dist`** folder you just unzipped.
9. Pin the extension to your toolbar and you are ready to go!

### Option B: Build from Source (For Developers)
```bash
git clone https://github.com/NULL2000K/NULL2000K_fetch_DomXss.git
cd NULL2000K_fetch_DomXss
npm install
```
---

## ⚠️ Important Note About Permissions (Debugger)

To provide the most advanced detection capabilities, **NULL200OK_fetch_DomXss** includes a feature called **Deep DOMPurify**. This feature uses the Chrome DevTools Protocol (CDP) to attach a debugger and inspect sanitizer configurations hidden inside complex JavaScript bundles (like Webpack).

Because of this, the extension requests the `debugger` permission. 

**What to expect during installation:**
*   Chrome will show a warning message: *"Read and change all your data on all websites"* or *"Debugging this browser"*. 
*   **Do not be alarmed.** This is standard for security tools that need to inspect page execution in real-time.
*   The debugger is **only** attached to a specific tab when you explicitly click the **"Enable Deep DOMPurify"** button in the extension popup. 
*   You can safely close the debugger at any time by clicking the yellow warning bar at the top of your browser.

Since this tool is fully open-source, you are welcome to review the code in `lib/debugger-adapter.js` to see exactly how the debugger is used.

### 🛡️ Features :
**Runtime DOM XSS — Detects flows into innerHTML, document.write, eval, setTimeout, and more.**

**Taint Tracking — Traces indirect flows (e.g., const x = location.hash; el.innerHTML = x.slice(1)).**

**Static Analysis — Uses Acorn to build CFG and PDG graphs to find vulnerabilities before they execute.**

**DOMPurify Awareness — Detects dangerous sanitizer configurations (e.g., ADD_ATTR(fn)).**

**Deep Instrumentation — Optional CDP debugger mode to catch bundled DOMPurify instances.**

**Prototype Pollution — Detects __proto__ injections.**

**Export & Reporting — Export findings to JSON or SARIF 2.1.0 (works with GitHub Code Scanning).**

---

### 📖 How to Use :
**Browse any website. The extension runs automatically.**

**To test it, navigate to a page and append a payload to the URL hash, e.g., #<img src=x onerror=alert(1)>.**

**If a vulnerability is detected, a draggable overlay will appear in the top-right corner.**

**Open the Developer Tools (F12) and go to the NULL2000K DomXss tab for a detailed table of findings**.

**Click the extension icon in the toolbar to Export JSON, Export SARIF, or enable Deep DOMPurify.**

---

### 👨‍💻 Author :
**NULL2000K — Built for authorized penetration testing and DOM XSS research only.**

**⚠️ This tool is intended for authorized security testing. Using it against systems you do not have explicit permission to test is illegal and unethical.**
