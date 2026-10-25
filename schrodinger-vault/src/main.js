// bridges to call Rust commands from JavaScript
const { invoke } = window.__TAURI__.core;
const { ask } = window.__TAURI__.dialog;

const PASS_VIS_DURATION = 10000; // Time till password is hidden (10s)
const BULLETS = "••••••••";

// Idle timeout auto-lock timer
const IDLE_TIMEOUT = 5 * 60 * 1000; // 5 mins
let idleTimer = null;

function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer);

    idleTimer = setTimeout(() => {
        console.log("User idle for 5 minutes. Auto-locking...");
        lockVault();
    }, IDLE_TIMEOUT);
}

// Register activity events to reset timer
function registerIdleListeners() {
    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach(ev => {
        document.addEventListener(ev, resetIdleTimer, { passive: true });
    });
}

// --- Password reveal ---
function hideSecret(secretSpan, showBtn) {
    if (showBtn._hideTimer) {
        clearTimeout(showBtn._hideTimer);
        showBtn._hideTimer = null;
    }
    secretSpan.textContent = BULLETS;
    secretSpan.classList.remove("revealed");
    showBtn.dataset.visible = "false";
    showBtn.setAttribute("aria-label", "Show secret");
    showBtn.title = "Show secret";
    showBtn.disabled = false;
}

async function toggleSecret(id, secretSpan, showBtn, errorMsg) {
    errorMsg.textContent = "";
    if (showBtn.dataset.visible === "true") {
        hideSecret(secretSpan, showBtn);
        return;
    }

    try {
        showBtn.disabled = true;
        const value = await invoke("vault_get", { id });
        secretSpan.textContent = value;
        secretSpan.classList.add("revealed");
        showBtn.dataset.visible = "true";
        showBtn.setAttribute("aria-label", "Hide secret");
        showBtn.title = "Hide secret";
        showBtn.disabled = false;
        showBtn._hideTimer = setTimeout(() => {
            hideSecret(secretSpan, showBtn);
        }, PASS_VIS_DURATION);
    } catch (err) {
        console.log("Show failed:", err);
        errorMsg.textContent = err;
        showBtn.disabled = false;
    }
}

// -- Toast notification --
function showToast(message, duration = 3000) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => {
        toast.classList.remove("show");
    }, duration);

}

// --- Copy password ---
async function copySecret(id) {
    let value = null;
    try {
        value = await invoke("vault_get", { id });
        await invoke("copy_secret_to_clipboard", {
            text: value,
            clearAfterMs: PASS_VIS_DURATION,
        });
        showToast("Copied");
    } catch (err) {
        console.log("Copy failed:", err);
    } finally {
        value = null;
    }
}

// --- Delete an entry ---
async function deleteEntry(id, row, label) {
    const ok = await ask(`Delete entry: "${label}"?`, {
        title: "Tauri",
        kind: "warning",
    });
    if (!ok) return;

    try {
        await invoke("vault_delete", { id });
        row.remove();
        console.log("JS done with deleteEntry: ", id)
    } catch (err) {
        console.log("Delete failed:", err);
    }
}

function setupEditEntryDialog() {
    const dialog = document.getElementById("edit-entry-dialog");
    const form = document.getElementById("edit-entry-form");
    const cancelBtn = document.getElementById("cancel-edit-entry");
    const submitBtn = document.getElementById("submit-edit-entry");
    const nameInput = document.getElementById("edit-entry-name");
    const typeInput = document.getElementById("edit-entry-type");
    const namespaceInput = document.getElementById("edit-entry-namespace");
    const secretInput = document.getElementById("edit-entry-secret");
    const notesInput = document.getElementById("edit-entry-notes");
    const msg = document.getElementById("edit-entry-msg");

    if (!dialog || !form) return;

    const clearForm = () => {
        form.reset();
        form.dataset.entryId = "";
        msg.textContent = "";
        secretInput.value = "";
    };

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    dialog.addEventListener("close", () => {
        secretInput.value = "";
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const id = Number(form.dataset.entryId);
        const name = nameInput.value;
        const recordType = typeInput.value;
        const namespace = namespaceInput.value;
        let secret = secretInput.value;
        const notesRaw = notesInput.value;
        const notes = notesRaw.trim().length ? notesRaw : null;

        if (!id) {
            msg.textContent = "No entry selected.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Saving...";
        try {
            await invoke("vault_update", { id, name, recordType, namespace, secret, notes });
            clearForm();
            dialog.close();
            await loadEntries();
            showToast("Entry updated");
        } catch (err) {
            console.error("Entry update failed:", err);
            msg.textContent = String(err);
        } finally {
            secret = null;
            submitBtn.disabled = false;
            submitBtn.textContent = "Save";
        }
    });
}

async function openEditEntry(entry) {
    const dialog = document.getElementById("edit-entry-dialog");
    const form = document.getElementById("edit-entry-form");
    const nameInput = document.getElementById("edit-entry-name");
    const typeInput = document.getElementById("edit-entry-type");
    const namespaceInput = document.getElementById("edit-entry-namespace");
    const secretInput = document.getElementById("edit-entry-secret");
    const notesInput = document.getElementById("edit-entry-notes");
    const msg = document.getElementById("edit-entry-msg");

    if (!dialog || !form) return;

    msg.textContent = "";
    form.dataset.entryId = String(entry.id);
    nameInput.value = entry.label;
    typeInput.value = entry.record_type;
    namespaceInput.value = entry.namespace;
    notesInput.value = entry.notes || "";
    secretInput.value = "";
    dialog.showModal();
    nameInput.focus();

    try {
        secretInput.value = await invoke("vault_get", { id: entry.id });
    } catch (err) {
        console.error("Loading entry password failed:", err);
        msg.textContent = String(err);
    }
}

// --- Lock Vault ---
async function lockVault() {
    try {
        // Call the Rust command
        await invoke("lock_vault");

        // Redirect to unlock page
        window.location.replace("unlock.html");
    } catch (err) {
        console.error("Error locking vault:", err);
        showToast("Failed to lock vault");
    }
}

function setupChangePasswordDialog() {
    const openBtn = document.getElementById("change-password-btn");
    const dialog = document.getElementById("change-password-dialog");
    const form = document.getElementById("change-password-form");
    const cancelBtn = document.getElementById("cancel-change-password");
    const submitBtn = document.getElementById("submit-change-password");
    const currentEl = document.getElementById("current-master-password");
    const newEl = document.getElementById("new-master-password");
    const confirmEl = document.getElementById("confirm-master-password");
    const msg = document.getElementById("change-password-msg");

    if (!openBtn || !dialog || !form) return;

    [currentEl, newEl, confirmEl].forEach((input) => {
        input.addEventListener("keydown", (event) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            form.requestSubmit();
        });
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
    };

    openBtn.addEventListener("click", () => {
        clearForm();
        dialog.showModal();
        currentEl.focus();
    });

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const currentPassword = currentEl.value;
        const newPassword = newEl.value;
        const confirmPassword = confirmEl.value;

        if (newPassword.length < 10) {
            msg.textContent = "Use at least 10 characters.";
            return;
        }
        if (newPassword !== confirmPassword) {
            msg.textContent = "New passwords do not match.";
            return;
        }
        if (currentPassword === newPassword) {
            msg.textContent = "Choose a different new password.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Updating...";
        try {
            await invoke("change_master_password", { currentPassword, newPassword });
            clearForm();
            dialog.close();
            showToast("Master password updated");
        } catch (err) {
            console.error("Password change failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Update";
        }
    });
}

function setupFactoryResetDialog() {
    const openBtn = document.getElementById("factory-reset-btn");
    const dialog = document.getElementById("factory-reset-dialog");
    const form = document.getElementById("factory-reset-form");
    const cancelBtn = document.getElementById("cancel-factory-reset");
    const submitBtn = document.getElementById("submit-factory-reset");
    const passwordEl = document.getElementById("reset-master-password");
    const msg = document.getElementById("factory-reset-msg");

    if (!openBtn || !dialog || !form) return;

    passwordEl.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        form.requestSubmit();
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
    };

    openBtn.addEventListener("click", () => {
        clearForm();
        dialog.showModal();
        passwordEl.focus();
    });

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const masterPassword = passwordEl.value;
        if (!masterPassword) {
            msg.textContent = "Enter the master password to reset.";
            return;
        }

        const ok = await ask("This will permanently delete the vault. Continue?", {
            title: "Factory Reset",
            kind: "warning",
        });
        if (!ok) return;

        submitBtn.disabled = true;
        submitBtn.textContent = "Resetting...";
        try {
            await invoke("factory_reset_vault", { masterPassword });
            clearForm();
            dialog.close();
            showToast("Vault reset");
            window.location.replace("create.html");
        } catch (err) {
            console.error("Factory reset failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Reset Vault";
        }
    });
}

async function refreshKeyDerivationStatus() {
    const label = document.getElementById("current-kdf-label");
    const button = document.getElementById("change-kdf-btn");
    if (!label) return;

    try {
        const status = await invoke("key_derivation_status");
        label.textContent = status.label;
        label.dataset.kdf = status.kdf;
        if (button) button.disabled = false;
    } catch (err) {
        console.error("Key derivation status failed:", err);
        label.textContent = "Unavailable";
        if (button) button.disabled = true;
    }
}

function setupKeyDerivationDialog() {
    const openBtn = document.getElementById("change-kdf-btn");
    const dialog = document.getElementById("change-kdf-dialog");
    const form = document.getElementById("change-kdf-form");
    const cancelBtn = document.getElementById("cancel-change-kdf");
    const submitBtn = document.getElementById("submit-change-kdf");
    const passwordEl = document.getElementById("kdf-master-password");
    const msg = document.getElementById("change-kdf-msg");
    const currentLabel = document.getElementById("current-kdf-label");

    if (!openBtn || !dialog || !form) return;

    passwordEl.addEventListener("keydown", (event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        form.requestSubmit();
    });

    const clearForm = () => {
        form.reset();
        msg.textContent = "";
        const currentKdf = currentLabel?.dataset.kdf ?? "argon2id";
        const currentRadio = form.querySelector(`input[name="settings-kdf"][value="${currentKdf}"]`);
        if (currentRadio) currentRadio.checked = true;
    };

    openBtn.addEventListener("click", () => {
        clearForm();
        dialog.showModal();
        passwordEl.focus();
    });

    cancelBtn.addEventListener("click", () => {
        clearForm();
        dialog.close();
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        msg.textContent = "";

        const currentPassword = passwordEl.value;
        const kdf = form.querySelector('input[name="settings-kdf"]:checked')?.value;
        if (!currentPassword) {
            msg.textContent = "Enter the current master password.";
            return;
        }
        if (!kdf) {
            msg.textContent = "Choose a key derivation mode.";
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Updating...";
        try {
            await invoke("change_key_derivation_mode", { currentPassword, kdf });
            clearForm();
            dialog.close();
            await refreshKeyDerivationStatus();
            showToast("Key derivation mode updated");
        } catch (err) {
            console.error("Key derivation mode change failed:", err);
            msg.textContent = String(err);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Update Mode";
        }
    });
}

function setupTabs() {
    const tabButtons = document.querySelectorAll("[data-tab-target]");
    const panels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const targetId = button.dataset.tabTarget;
            tabButtons.forEach((btn) => btn.classList.toggle("active", btn === button));
            panels.forEach((panel) => panel.classList.toggle("active", panel.id === targetId));
            if (targetId === "applications-panel") {
                loadApplicationAccess();
            }
        });
    });
}

function applicationAccessCard(item, kind) {
    const card = document.createElement("article");
    card.className = "application-access-card";

    const details = document.createElement("div");
    const title = document.createElement("h4");
    title.textContent = item.application_name;
    const namespace = document.createElement("p");
    namespace.textContent = `Namespace: ${item.namespace}`;
    const fingerprint = document.createElement("code");
    fingerprint.textContent = item.public_key_fingerprint;
    details.append(title, namespace, fingerprint);

    if (kind !== "pending") {
        const clientId = document.createElement("p");
        clientId.className = "client-id";
        clientId.textContent = `Client ID: ${item.client_id}`;
        details.append(clientId);
    }

    const actions = document.createElement("div");
    actions.className = "application-access-actions";

    if (kind === "pending") {
        const reject = document.createElement("button");
        reject.type = "button";
        reject.className = "btn-secondary";
        reject.textContent = "Reject";
        reject.addEventListener("click", async () => {
            await invoke("ipc_reject_registration", { pendingId: item.pending_id });
            await loadApplicationAccess();
        });

        const approve = document.createElement("button");
        approve.type = "button";
        approve.className = "btn-accent";
        approve.textContent = "Approve";
        approve.addEventListener("click", async () => {
            const ok = await ask(
                `Approve ${item.application_name} for namespace “${item.namespace}”?`,
                { title: "Approve Local Application", kind: "warning" },
            );
            if (!ok) return;
            await invoke("ipc_approve_registration", { pendingId: item.pending_id });
            showToast("Application approved");
            await loadApplicationAccess();
        });
        actions.append(reject, approve);
    } else {
        const status = document.createElement("span");
        status.className = item.revoked ? "client-status revoked" : "client-status active";
        status.textContent = item.revoked ? "Revoked" : "Active";
        actions.append(status);

        if (!item.revoked) {
            const revoke = document.createElement("button");
            revoke.type = "button";
            revoke.className = "delete";
            revoke.textContent = "Revoke";
            revoke.addEventListener("click", async () => {
                const ok = await ask(`Revoke access for ${item.application_name}?`, {
                    title: "Revoke Local Application",
                    kind: "warning",
                });
                if (!ok) return;
                await invoke("ipc_revoke_client", { clientId: item.client_id });
                showToast("Application revoked");
                await loadApplicationAccess();
            });
            actions.append(revoke);
        }
    }

    card.append(details, actions);
    return card;
}

async function loadApplicationAccess() {
    const pendingList = document.getElementById("pending-applications-list");
    const registeredList = document.getElementById("registered-applications-list");
    const socketPath = document.getElementById("ipc-socket-path");
    if (!pendingList || !registeredList || !socketPath) return;

    try {
        const [path, pending, clients] = await Promise.all([
            invoke("ipc_socket_path"),
            invoke("ipc_list_pending_registrations"),
            invoke("ipc_list_clients"),
        ]);
        socketPath.textContent = path;
        pendingList.replaceChildren();
        registeredList.replaceChildren();

        if (!pending.length) pendingList.textContent = "No pending requests.";
        else pending.forEach((item) => pendingList.appendChild(applicationAccessCard(item, "pending")));

        if (!clients.length) registeredList.textContent = "No registered applications.";
        else clients.forEach((item) => registeredList.appendChild(applicationAccessCard(item, "registered")));
    } catch (err) {
        console.error("Application access refresh failed:", err);
        pendingList.textContent = "Application access information is unavailable.";
        registeredList.replaceChildren();
    }
}


// --- Make entry row ---
function renderRow(e) {
    const tpl = document.getElementById('entry-row-tpl');
    const row = tpl.content.firstElementChild.cloneNode(true);

    row.dataset.id = e.id;

    row.querySelector('.entry-label').textContent = e.label;
    row.querySelector('.entry-record-type').textContent = e.record_type;
    row.querySelector('.entry-namespace').textContent = e.namespace;
    row.querySelector('.entry-notes').textContent = (e.notes == null ? '' : e.notes);

    const secretSpan = row.querySelector('.secret');
    const errorMsg = row.querySelector('.errorMsg');
    secretSpan.textContent = BULLETS;
    const showBtn = row.querySelector('.show');
    showBtn.dataset.visible = "false";
    showBtn.addEventListener('click', () => toggleSecret(e.id, secretSpan, showBtn, errorMsg));

    row.querySelector('.copy').addEventListener('click', () => copySecret(e.id));
    row.querySelector('.edit').addEventListener('click', () => openEditEntry(e));
    row.querySelector('.delete').addEventListener('click', () => deleteEntry(e.id, row, e.label));

    return row;
}

// --- Load all entries into html list ---
let entryCache = [];

function entryMatchesSearch(entry, query) {
    if (!query) return true;
    const haystack = [
        entry.label,
        entry.record_type,
        entry.namespace,
        entry.notes || "",
    ].join(" ").toLowerCase();
    return haystack.includes(query);
}

function renderEntries(items) {
    const container = document.getElementById("entry-list");
    container.innerHTML = "";

    if (!items || items.length === 0) {
        container.textContent = entryCache.length ? "No matching entries." : "No entries yet.";
        return;
    }

    for (const e of items) {
        container.appendChild(renderRow(e));
    }
}

function applyEntrySearch() {
    const searchEl = document.getElementById("entry-search");
    const query = (searchEl?.value || "").trim().toLowerCase();
    renderEntries(entryCache.filter((entry) => entryMatchesSearch(entry, query)));
}

async function loadEntries() {
    try {
        entryCache = await invoke("vault_list");
        applyEntrySearch();
    } catch (err) {
        console.log("Error fetching list of entries:", err);
    }
}

// --- Add a new entry ---
let nameEl;
let recordTypeEl;
let namespaceEl;
let secretEl;
let notesEl;
nameEl = document.querySelector("#secret-name");
recordTypeEl = document.querySelector("#record-type");
namespaceEl = document.querySelector("#namespace");
secretEl = document.querySelector("#secret-value");
notesEl = document.querySelector("#notes");
document.querySelector("#add-entry").addEventListener("submit", (e) => {
    e.preventDefault();
    addEntry();
});

async function addEntry() {
    const name = nameEl.value;
    const recordType = recordTypeEl.value;
    const namespace = namespaceEl.value;
    let secret = secretEl.value;
    // clear sensitive DOM value immediately
    secretEl.value = "";
    const notesRaw = notesEl.value;
    const notes = notesRaw.trim().length ? notesRaw : null;

    try {
        await invoke("vault_add", { name, recordType, namespace, secret, notes });
        // clear inputs after add
        nameEl.value = "";
        notesEl.value = "";

        // reload list with new entry
        await loadEntries();
    } catch (err) {
        console.log("Error adding entry: ", err);
    } finally {
        // ensure sensitive var is cleared
        secret = null;
    }
}


window.addEventListener("DOMContentLoaded", async(e) => {
    e.preventDefault();
    const lockBtn = document.getElementById("lock-vault-btn");
    if (lockBtn) {
        lockBtn.addEventListener("click", lockVault);
    }
    setupChangePasswordDialog();
    setupEditEntryDialog();
    setupKeyDerivationDialog();
    setupFactoryResetDialog();
    setupTabs();
    document.getElementById("refresh-applications-btn")?.addEventListener("click", loadApplicationAccess);
    const searchEl = document.getElementById("entry-search");
    if (searchEl) {
        searchEl.addEventListener("input", applyEntrySearch);
    }

    // start idle auto-locking
    registerIdleListeners();
    resetIdleTimer();

    try {
        const initialized = await invoke("vault_exists");
        if (!initialized) {
            return window.location.replace("create.html");
        }

        const { loaded } = await invoke("vault_session_status");
        if (!loaded) return window.location.replace("unlock.html");

        await refreshKeyDerivationStatus();
        await loadEntries();
    } catch (err) {
        console.error("Init check failed:", err);
        // If anything goes sideways, send to unlock to be safe.
        window.location.replace("unlock.html");
    }
});
