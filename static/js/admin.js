// Admin panel JavaScript - sidebar navigation and page switching

// Initialize sidebar state from localStorage
const sidebar = document.getElementById('sidebar');
const toggleBtn = document.getElementById('toggleBtn');
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page-content');

// Load collapsed state from localStorage
const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
if (isCollapsed) {
    sidebar.classList.add('collapsed');
}

// Toggle sidebar
toggleBtn.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
    const collapsed = sidebar.classList.contains('collapsed');
    localStorage.setItem('sidebarCollapsed', collapsed);
});

// Page navigation
function navigateToPage(pageName) {
    // Update active nav item
    navItems.forEach(item => {
        if (item.dataset.page === pageName) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Show active page
    pages.forEach(page => {
        if (page.id === `page-${pageName}`) {
            page.classList.add('active');
        } else {
            page.classList.remove('active');
        }
    });

    // Update URL without reload
    const url = pageName === 'home' ? '/admin' : `/admin/${pageName}`;
    window.history.pushState({ page: pageName }, '', url);

    // Load page content if needed
    loadPageContent(pageName);
}

// Handle nav item clicks
navItems.forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const pageName = item.dataset.page;
        navigateToPage(pageName);
    });
});

// Handle browser back/forward
window.addEventListener('popstate', (e) => {
    if (e.state?.page) {
        // Update UI without pushing new state
        navItems.forEach(item => {
            if (item.dataset.page === e.state.page) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        pages.forEach(page => {
            if (page.id === `page-${e.state.page}`) {
                page.classList.add('active');
            } else {
                page.classList.remove('active');
            }
        });

        loadPageContent(e.state.page);
    }
});

// Permission metadata (from static/permissions.json) - cached after first load
let permissionMetadata = { permissions: {}, categories: {} };
let permissionMetadataLoaded = false;
let appAccessEntries = [];
let appEventsCatalog = [];
let appsCatalog = [];
let appsPageInitialized = false;
let appsSearchTerm = '';
let appsStatusFilter = 'all';

async function ensurePermissionMetadata() {
    if (permissionMetadataLoaded) return permissionMetadata;

    try {
        const response = await secureFetch('/static/permissions.json');
        const data = await response.json();
        permissionMetadata = {
            permissions: data.permissions || {},
            categories: data.categories || {}
        };
    } catch (error) {
        console.warn('Failed to load permission metadata', error);
        permissionMetadata = { permissions: {}, categories: {} };
    }

    permissionMetadataLoaded = true;
    return permissionMetadata;
}

// Load page content dynamically
async function loadPageContent(pageName) {
    const pageElement = document.getElementById(`page-${pageName}`);

    // Handle attendees page with DataTables
    if (pageName === 'attendees') {
        // Check if DataTables is already initialized
        if ($.fn.DataTable.isDataTable('#attendees-table')) {
            return; // Already initialized
        }

        // Initialize DataTables
        $('#attendees-table').DataTable({
            ajax: {
                url: '/admin/users/data',
                dataSrc: 'data'
            },
            columns: [
                {
                    data: 'email',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'email', rowData));
                    }
                },
                {
                    data: 'legal_name',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'legal_name', rowData));
                    }
                },
                {
                    data: 'preferred_name',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'preferred_name', rowData));
                    }
                },
                {
                    data: 'pronouns',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'pronouns', rowData));
                    }
                },
                {
                    data: 'dob',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'dob', rowData));
                    }
                },
                {
                    data: 'discord_id',
                    defaultContent: '',
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditable(td, 'discord_id', rowData));
                    }
                },
                {
                    data: 'events',
                    render: function(data, type, row) {
                        if (!data || data.length === 0) {
                            return '<span class="text-muted">No events</span>';
                        }
                        return data.map(eventId => {
                            return `<span class="event-tag event-${eventId}">${eventId}</span>`;
                        }).join(' ');
                    },
                    createdCell: function(td, cellData, rowData) {
                        td.classList.add('editable');
                        td.addEventListener('click', () => makeEditableEvents(td, rowData));
                    }
                }
            ],
            pageLength: 1000,
            lengthMenu: [[25, 50, 100, 500, 1000, -1], [25, 50, 100, 500, 1000, "All"]],
            order: [[0, 'asc']],
            scrollY: 'calc(100vh - 250px)',
            scrollCollapse: true,
            paging: true,
            responsive: false
        });
        return;
    }

    // Handle events page
    if (pageName === 'events') {
        if ($.fn.DataTable.isDataTable('#events-table')) {
            return; // Already initialized
        }
        loadEventsPage();
        return;
    }

    // Handle API keys page
    if (pageName === 'keys') {
        if ($.fn.DataTable.isDataTable('#keys-table')) {
            return; // Already initialized
        }
        await loadKeysPage();
        return;
    }

    // Handle admins page
    if (pageName === 'admins') {
        if ($.fn.DataTable.isDataTable('#admins-table')) {
            return; // Already initialized
        }
        loadAdminsPage();
        return;
    }

    // Handle apps page
    if (pageName === 'apps') {
        if (!appsPageInitialized) {
            loadAppsPage();
        } else {
            await refreshAppsCatalog();
        }
        return;
    }

    // Skip if already loaded (has content other than loading message)
    if (pageElement.querySelector('.loading') === null) {
        return;
    }

    // TODO: Implement actual content loading for other pages
    // For now, just show placeholder
    pageElement.innerHTML = `<h1>${pageName.charAt(0).toUpperCase() + pageName.slice(1)}</h1><p>Content for ${pageName} page.</p>`;
}

// Initialize current page based on URL
const currentPath = window.location.pathname;
let initialPage = 'home';
if (currentPath.includes('/attendees')) initialPage = 'attendees';
else if (currentPath.includes('/events')) initialPage = 'events';
else if (currentPath.includes('/keys')) initialPage = 'keys';
else if (currentPath.includes('/admins')) initialPage = 'admins';
else if (currentPath.includes('/apps')) initialPage = 'apps';

navigateToPage(initialPage);

// Inline editing functionality
let editingCell = null;
let editingRow = null;

function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.className = `toast ${isError ? 'error' : 'success'}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function makeEditable(cell, field, rowData) {
    if (editingCell) return;

    editingCell = cell;
    editingRow = rowData;

    const currentValue = cell.textContent;
    const originalValue = currentValue;

    const input = document.createElement('input');
    input.type = 'text';
    input.value = currentValue;
    input.className = 'cell-edit-input';

    cell.textContent = '';
    cell.appendChild(input);
    input.focus();
    input.select();

    let saveTimeout;

    function save() {
        clearTimeout(saveTimeout);
        const newValue = input.value.trim();

        if (newValue === originalValue) {
            cancel();
            return;
        }

        // Optimistic update
        cell.textContent = newValue;
        cell.classList.add('editing');
        editingCell = null;
        editingRow = null;

        // Save to server
        saveTimeout = setTimeout(async () => {
            try {
                const response = await secureFetch('/admin/update-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: rowData.email,
                        field: field,
                        value: newValue
                    })
                });

                const data = await response.json();

                if (data.success) {
                    cell.classList.remove('editing');
                    showToast('Saved successfully');
                    rowData[field] = newValue;
                } else {
                    cell.textContent = originalValue;
                    cell.classList.remove('editing');
                    showToast('Failed to save: ' + (data.error || 'Unknown error'), true);
                }
            } catch (error) {
                cell.textContent = originalValue;
                cell.classList.remove('editing');
                showToast('Failed to save: ' + error.message, true);
            }
        }, 100);
    }

    function cancel() {
        clearTimeout(saveTimeout);
        cell.textContent = originalValue;
        editingCell = null;
        editingRow = null;
    }

    input.addEventListener('blur', save);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            save();
        } else if (e.key === 'Escape') {
            e.preventDefault();
            cancel();
        }
    });
}

function makeEditableEvents(cell, rowData) {
    if (editingCell) return;

    editingCell = cell;
    editingRow = rowData;

    const currentEvents = rowData.events || [];
    const currentValue = currentEvents.join(', ');
    const originalEvents = [...currentEvents];

    const input = document.createElement('input');
    input.type = 'text';
    input.value = currentValue;
    input.className = 'cell-edit-input';
    input.placeholder = 'e.g., counterspell, scrapyard';

    cell.textContent = '';
    cell.appendChild(input);
    input.focus();
    input.select();

    let saveTimeout;

    function save() {
        clearTimeout(saveTimeout);
        const newValue = input.value.trim();
        const newEvents = newValue ? newValue.split(',').map(e => e.trim()).filter(e => e) : [];

        if (JSON.stringify(newEvents) === JSON.stringify(originalEvents)) {
            cancel();
            return;
        }

        // Optimistic update
        const html = newEvents.length === 0
            ? '<span class="text-muted">No events</span>'
            : newEvents.map(eventId => `<span class="event-tag event-${eventId}">${eventId}</span>`).join(' ');
        cell.innerHTML = html;
        cell.classList.add('editing');
        editingCell = null;
        editingRow = null;

        // Save to server
        saveTimeout = setTimeout(async () => {
            try {
                const response = await secureFetch('/admin/update-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: rowData.email,
                        field: 'events',
                        value: newEvents
                    })
                });

                const data = await response.json();

                if (data.success) {
                    cell.classList.remove('editing');
                    showToast('Saved successfully');
                    rowData.events = newEvents;
                } else {
                    const originalHtml = originalEvents.length === 0
                        ? '<span class="text-muted">No events</span>'
                        : originalEvents.map(eventId => `<span class="event-tag event-${eventId}">${eventId}</span>`).join(' ');
                    cell.innerHTML = originalHtml;
                    cell.classList.remove('editing');
                    showToast('Failed to save: ' + (data.error || 'Unknown error'), true);
                }
            } catch (error) {
                const originalHtml = originalEvents.length === 0
                    ? '<span class="text-muted">No events</span>'
                    : originalEvents.map(eventId => `<span class="event-tag event-${eventId}">${eventId}</span>`).join(' ');
                cell.innerHTML = originalHtml;
                cell.classList.remove('editing');
                showToast('Failed to save: ' + error.message, true);
            }
        }, 100);
    }

    function cancel() {
        clearTimeout(saveTimeout);
        const originalHtml = originalEvents.length === 0
            ? '<span class="text-muted">No events</span>'
            : originalEvents.map(eventId => `<span class="event-tag event-${eventId}">${eventId}</span>`).join(' ');
        cell.innerHTML = originalHtml;
        editingCell = null;
        editingRow = null;
    }

    input.addEventListener('blur', save);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            save();
        } else if (e.key === 'Escape') {
            e.preventDefault();
            cancel();
        }
    });
}

// API Keys Page
async function loadKeysPage() {
    await ensurePermissionMetadata();

    const pageElement = document.getElementById('page-keys');
    pageElement.innerHTML = `
        <div class="page-header">
            <h1>API Keys</h1>
            <button class="btn-primary" id="add-key-btn">Create API Key</button>
        </div>
        <table id="keys-table" class="display table-full-width">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Created By</th>
                    <th>Permissions</th>
                    <th>Rate Limit</th>
                    <th>Last Used</th>
                    <th>Actions</th>
                </tr>
            </thead>
        </table>
    `;

    document.getElementById('add-key-btn').addEventListener('click', () => openApiKeyModal());

    const table = $('#keys-table').DataTable({
        ajax: {
            url: '/admin/api_keys',
            dataSrc: 'keys'
        },
        columns: [
            {
                data: 'name',
                render: function(data) {
                    return data || '<span class="muted">Untitled</span>';
                }
            },
            { data: 'created_by', defaultContent: '' },
            {
                data: 'permissions',
                render: function(data) {
                    return renderPermissionBadges(data);
                }
            },
            {
                data: 'rate_limit_rpm',
                render: function(data) {
                    if (data === 0) return '<span class="muted">Unlimited</span>';
                    if (typeof data === 'number') return `${data} / min`;
                    return '<span class="muted">n/a</span>';
                }
            },
            {
                data: 'last_used_at',
                render: function(data) {
                    if (!data) return '<span class="muted">Never</span>';
                    const date = new Date(data);
                    return isNaN(date.getTime()) ? data : date.toLocaleString();
                }
            },
            {
                data: 'id',
                render: function(data) {
                    return `
                        <button class="btn-secondary btn-view-logs" data-key-id="${data}">Logs</button>
                        <button class="btn-secondary btn-edit-key" data-key-id="${data}">Edit</button>
                        <button class="btn-danger btn-delete-key" data-key-id="${data}">Delete</button>
                    `;
                }
            }
        ],
        pageLength: 25,
        order: [[4, 'desc']]
    });

    $('#keys-table').on('click', '.btn-edit-key', function() {
        const rowData = table.row($(this).closest('tr')).data();
        openApiKeyModal(rowData);
    });

    $('#keys-table').on('click', '.btn-delete-key', function() {
        const rowData = table.row($(this).closest('tr')).data();
        deleteApiKey(rowData);
    });

    $('#keys-table').on('click', '.btn-view-logs', function() {
        const rowData = table.row($(this).closest('tr')).data();
        viewApiKeyLogs(rowData);
    });
}

function renderPermissionBadges(permissions) {
    if (!permissions || permissions.length === 0) {
        return '<span class="muted">None</span>';
    }

    return permissions.map(perm => {
        const def = permissionMetadata.permissions[perm];
        const category = def ? permissionMetadata.categories[def.category] : null;
        const color = category?.color || '#007bff';
        const displayName = def?.name || perm;
        return `<span class="permission-pill" style="border: 1px solid ${color}; color: ${color};">${displayName}</span>`;
    }).join(' ');
}

async function openApiKeyModal(keyData = null) {
    await ensurePermissionMetadata();

    const title = document.getElementById('api-key-modal-title');
    const idInput = document.getElementById('api-key-id');
    const nameInput = document.getElementById('api-key-name');
    const rateInput = document.getElementById('api-key-rate-limit');

    title.textContent = keyData ? 'Edit API Key' : 'Add API Key';
    idInput.value = keyData?.id || '';
    nameInput.value = keyData?.name || '';
    rateInput.value = typeof keyData?.rate_limit_rpm === 'number' ? keyData.rate_limit_rpm : 60;

    renderPermissionChecklist(keyData?.permissions || []);
    openModal('api-key-modal');
}

function renderPermissionChecklist(selectedPermissions) {
    const container = document.getElementById('api-key-permissions');
    const selectedSet = new Set(selectedPermissions || []);
    const grouped = {};

    Object.entries(permissionMetadata.permissions).forEach(([key, def]) => {
        const category = def.category || 'Other';
        if (!grouped[category]) grouped[category] = [];
        grouped[category].push({ key, def });
    });

    const categories = Object.keys(grouped).sort();
    if (categories.length === 0) {
        container.innerHTML = '<p class="muted">No permissions defined.</p>';
        return;
    }

    container.innerHTML = categories.map(cat => {
        const color = permissionMetadata.categories[cat]?.color || '#00ccff';
        const tiles = grouped[cat].map(item => {
            const checked = selectedSet.has(item.key) ? 'checked' : '';
            return `
                <div class="permission-tile">
                    <label>
                        <input type="checkbox" class="api-key-permission" value="${item.key}" ${checked}>
                        <div>
                            <strong>${item.def.name || item.key}</strong>
                            <span class="permission-pill" style="border: 1px solid ${color}; color: ${color}; background: #f6fbff;">${cat}</span>
                            <small>${item.def.description || ''}</small>
                        </div>
                    </label>
                </div>
            `;
        }).join('');

        return `
            <div class="permission-group">
                <h3>${cat}</h3>
                <div class="permission-grid">${tiles}</div>
            </div>
        `;
    }).join('');
}

function getSelectedApiPermissions() {
    return Array.from(document.querySelectorAll('.api-key-permission:checked')).map(cb => cb.value);
}

async function saveApiKey() {
    const id = document.getElementById('api-key-id').value;
    const name = document.getElementById('api-key-name').value.trim();
    const rateLimit = parseInt(document.getElementById('api-key-rate-limit').value, 10);
    const permissions = getSelectedApiPermissions();

    if (!name) {
        showToast('Name is required', true);
        return;
    }

    if (isNaN(rateLimit) || rateLimit < 0) {
        showToast('Rate limit must be 0 or a positive number', true);
        return;
    }

    const method = id ? 'PATCH' : 'POST';
    const url = id ? `/admin/api_keys/${id}` : '/admin/api_keys';

    try {
        const response = await secureFetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name,
                permissions,
                rate_limit_rpm: rateLimit
            })
        });

        const data = await response.json();
        if (!data.success) {
            showToast(data.error || 'Failed to save API key', true);
            return;
        }

        closeModal('api-key-modal');
        showToast(id ? 'API key updated' : 'API key created');

        if (!id && data.key) {
            document.getElementById('created-api-key').value = data.key;
            openModal('api-key-created-modal');
        }

        if ($.fn.DataTable.isDataTable('#keys-table')) {
            $('#keys-table').DataTable().ajax.reload();
        }
    } catch (error) {
        showToast(error.message || 'Failed to save API key', true);
    }
}

async function deleteApiKey(keyData) {
    if (!keyData?.id) return;
    if (!confirm(`Delete API key "${keyData.name || 'Untitled'}"?`)) return;

    try {
        const response = await secureFetch(`/admin/api_keys/${keyData.id}`, {
            method: 'DELETE',
        });

        const data = await response.json();
        if (data.success) {
            showToast('API key deleted');
            if ($.fn.DataTable.isDataTable('#keys-table')) {
                $('#keys-table').DataTable().ajax.reload();
            }
        } else {
            showToast(data.error || 'Failed to delete key', true);
        }
    } catch (error) {
        showToast(error.message || 'Failed to delete key', true);
    }
}

async function viewApiKeyLogs(keyData) {
    if (!keyData?.id) return;

    try {
        const response = await secureFetch(`/admin/api_keys/${keyData.id}/logs?limit=15`);
        const data = await response.json();

        if (!data.success) {
            showToast(data.error || 'Failed to load logs', true);
            return;
        }

        const logsContainer = document.getElementById('api-key-logs');
        const title = document.getElementById('api-key-logs-title');

        title.textContent = `Usage for ${data.key_name || keyData.name || 'API Key'}`;

        if (!data.logs || data.logs.length === 0) {
            logsContainer.innerHTML = '<p class="muted">No recent usage.</p>';
            openModal('api-key-logs-modal');
            return;
        }

        const logItems = data.logs.map(log => {
            const timestamp = log.timestamp || '';
            const date = new Date(timestamp);
            const formatted = isNaN(date.getTime()) ? timestamp : date.toLocaleString();
            const metadata = log.metadata && Object.keys(log.metadata).length > 0
                ? `<div class="meta">Metadata: ${JSON.stringify(log.metadata)}</div>`
                : '';
            return `<div class="log-row"><div><strong>${log.action || 'request'}</strong></div><div class="meta">${formatted}</div>${metadata}</div>`;
        }).join('');

        logsContainer.innerHTML = logItems;
        openModal('api-key-logs-modal');
    } catch (error) {
        showToast(error.message || 'Failed to load logs', true);
    }
}

// Admins Page
function loadAdminsPage() {
    const pageElement = document.getElementById('page-admins');
    pageElement.innerHTML = `
        <div class="page-header">
            <h1>Admins</h1>
            <button class="btn-primary" id="add-admin-btn">Add Admin</button>
        </div>
        <table id="admins-table" class="display table-full-width">
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Added By</th>
                    <th>Added At</th>
                    <th>Status</th>
                    <th>Permissions</th>
                    <th>Actions</th>
                </tr>
            </thead>
        </table>
    `;

    // Add event listener for Add Admin button
    document.getElementById('add-admin-btn').addEventListener('click', showAddAdminModal);

    // Initialize DataTable
    const table = $('#admins-table').DataTable({
        ajax: {
            url: '/admin/users/data',
            dataSrc: function(json) {
                // Filter for admins only
                return json.data.filter(user => user.is_admin);
            }
        },
        columns: [
            { data: 'email' },
            { data: 'added_by', defaultContent: 'system' },
            { data: 'added_at', defaultContent: 'N/A' },
            {
                data: 'is_active',
                render: function(data) {
                    return data ? '<span class="status-active">Active</span>' : '<span class="status-inactive">Inactive</span>';
                },
                defaultContent: '<span class="status-active">Active</span>'
            },
            {
                data: 'email',
                render: function(data) {
                    return `<button class="btn-secondary btn-manage-permissions" data-email="${data}">Manage</button>`;
                }
            },
            {
                data: 'email',
                render: function(data, type, row) {
                    if (row.added_by === 'system') {
                        return '<span class="text-muted">System Admin</span>';
                    }
                    return `<button class="btn-danger btn-remove-admin" data-email="${data}">Remove</button>`;
                }
            }
        ],
        pageLength: 25,
        order: [[2, 'desc']]
    });

    // Event delegation for dynamically created buttons
    $('#admins-table').on('click', '.btn-manage-permissions', function() {
        const email = $(this).data('email');
        showPermissionsModal(email);
    });

    $('#admins-table').on('click', '.btn-remove-admin', function() {
        const email = $(this).data('email');
        removeAdmin(email);
    });
}

// Apps Page
function loadAppsPage() {
    const pageElement = document.getElementById('page-apps');
    pageElement.innerHTML = `
        <div class="apps-shell">
            <div class="apps-toolbar">
                <div>
                    <h1>OAuth Apps</h1>
                    <p class="text-muted">Manage app metadata, access controls, and credentials.</p>
                </div>
                <button class="btn-primary" id="add-app-btn">New App</button>
            </div>

            <div class="apps-filters">
                <input type="text" id="apps-search" placeholder="Search apps by name, client ID, or owner" />
                <div class="apps-filter-buttons">
                    <button class="btn-secondary app-filter-btn active" data-filter="all">All</button>
                    <button class="btn-secondary app-filter-btn" data-filter="active">Active</button>
                    <button class="btn-secondary app-filter-btn" data-filter="inactive">Inactive</button>
                </div>
            </div>

            <div id="apps-list" class="apps-list"></div>
        </div>
    `;

    // Add event listener for Add App button
    document.getElementById('add-app-btn').addEventListener('click', showAddAppModal);
    document.getElementById('apps-search').addEventListener('input', (event) => {
        appsSearchTerm = event.target.value.trim().toLowerCase();
        renderAppsList();
    });

    document.querySelectorAll('.app-filter-btn').forEach(button => {
        button.addEventListener('click', () => {
            appsStatusFilter = button.dataset.filter || 'all';
            document.querySelectorAll('.app-filter-btn').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            renderAppsList();
        });
    });

    appsPageInitialized = true;
    refreshAppsCatalog();
}

function parseJsonList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

async function refreshAppsCatalog() {
    const listElement = document.getElementById('apps-list');
    if (!listElement) return;

    try {
        listElement.innerHTML = '<div class="loading">Loading apps...</div>';
        const response = await secureFetch('/admin/apps/data');
        if (response.status === 403) {
            listElement.innerHTML = '<p class="muted">You do not have permission to view apps.</p>';
            return;
        }
        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Failed to load apps');
        }
        appsCatalog = (data.data || []).map(app => ({
            ...app,
            redirect_uris_list: parseJsonList(app.redirect_uris),
            allowed_scopes_list: parseJsonList(app.allowed_scopes),
            app_type: app.app_type || 'oauth',
            skip_consent_screen: Boolean(app.skip_consent_screen),
        }));
        renderAppsList();
    } catch (error) {
        listElement.innerHTML = `<p class="muted">Failed to load apps: ${error.message}</p>`;
    }
}

function getFilteredApps() {
    return appsCatalog.filter(app => {
        if (appsStatusFilter === 'active' && !app.is_active) return false;
        if (appsStatusFilter === 'inactive' && app.is_active) return false;

        if (!appsSearchTerm) return true;
        const haystack = [
            app.name,
            app.client_id,
            app.created_by,
            ...(app.redirect_uris_list || []),
        ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
        return haystack.includes(appsSearchTerm);
    });
}

function appRowBadges(app) {
    const badges = [];
    badges.push(app.is_active ? '<span class="app-badge app-badge-active">Active</span>' : '<span class="app-badge app-badge-inactive">Inactive</span>');
    badges.push(app.allow_anyone ? '<span class="app-badge app-badge-open">All Users</span>' : '<span class="app-badge app-badge-restricted">Restricted</span>');
    if (app.skip_consent_screen) {
        badges.push('<span class="app-badge app-badge-internal">Skip Consent</span>');
    }
    badges.push(`<span class="app-badge app-badge-type">${app.app_type.toUpperCase()}</span>`);
    return badges.join('');
}

function renderAppsList() {
    const listElement = document.getElementById('apps-list');
    if (!listElement) return;

    const filteredApps = getFilteredApps();
    if (!filteredApps.length) {
        listElement.innerHTML = '<div class="apps-empty">No apps match your filters.</div>';
        return;
    }

    listElement.innerHTML = filteredApps.map(app => {
        const icon = app.icon || '🔗';
        const scopes = (app.allowed_scopes_list || []).map(scope => `<span class="permission-pill">${scope}</span>`).join('');
        const redirectPreview = app.redirect_uris_list && app.redirect_uris_list.length
            ? app.redirect_uris_list[0]
            : 'No redirect URI configured';
        const extraRedirects = Math.max((app.redirect_uris_list || []).length - 1, 0);
        const extraText = extraRedirects > 0 ? `<span class="text-muted"> +${extraRedirects} more</span>` : '';

        return `
            <div class="app-card" data-app-id="${app.id}">
                <div class="app-card-main">
                    <div class="app-card-head">
                        <div class="app-icon">${icon}</div>
                        <div class="app-title-wrap">
                            <h3>${app.name || 'Unnamed App'}</h3>
                            <div class="app-meta">
                                <code>${app.client_id || 'legacy-app'}</code>
                                <span>Owner: ${app.created_by || 'unknown'}</span>
                            </div>
                        </div>
                        <div class="app-badges">${appRowBadges(app)}</div>
                    </div>
                    <div class="app-card-body">
                        <p class="app-redirect">
                            <span class="text-muted">Redirect:</span>
                            <code>${redirectPreview}</code>${extraText}
                        </p>
                        <div class="app-scopes-line">${scopes || '<span class="text-muted">No scopes</span>'}</div>
                    </div>
                </div>
                <div class="app-card-actions">
                    <button class="btn-secondary app-action-edit" data-app-id="${app.id}">Edit</button>
                    <button class="btn-danger app-action-delete" data-app-id="${app.id}">Delete</button>
                </div>
            </div>
        `;
    }).join('');

    listElement.querySelectorAll('.app-action-edit').forEach(button => {
        button.addEventListener('click', () => editApp(button.dataset.appId));
    });
    listElement.querySelectorAll('.app-action-delete').forEach(button => {
        button.addEventListener('click', () => deleteApp(button.dataset.appId));
    });
}

// Events Page
function loadEventsPage() {
    const pageElement = document.getElementById('page-events');
    pageElement.innerHTML = `
        <div class="page-header">
            <h1>Events</h1>
        </div>
        <table id="events-table" class="display table-full-width">
            <thead>
                <tr>
                    <th>Event ID</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Attendees</th>
                    <th>Color</th>
                    <th>Discord Role ID</th>
                    <th>Legacy</th>
                </tr>
            </thead>
        </table>
    `;

    // Initialize DataTable
    $('#events-table').DataTable({
        ajax: {
            url: '/admin/events/data',
            dataSrc: 'data'
        },
        columns: [
            { data: 'id' },
            { data: 'name' },
            { data: 'description' },
            {
                data: 'user_count',
                render: function(data) {
                    return `<strong>${data}</strong>`;
                }
            },
            {
                data: 'color',
                render: function(data) {
                    return `<span class="color-swatch" style="background-color: #${data};"></span> <code>#${data}</code>`;
                }
            },
            {
                data: 'discord_role_id',
                render: function(data) {
                    return data ? `<code>${data}</code>` : '';
                }
            },
            {
                data: 'legacy',
                render: function(data) {
                    return data ? '<span class="text-warning">Yes</span>' : '<span class="text-muted">No</span>';
                }
            }
        ],
        pageLength: 25,
        order: [[3, 'desc']] // Sort by attendees descending
    });
}

// Modal helper functions - make them globally accessible
window.openModal = function(modalId) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById(modalId);
    overlay.classList.add('show');
    modal.classList.add('show');
}

window.closeModal = function(modalId) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById(modalId);
    overlay.classList.remove('show');
    modal.classList.remove('show');
}

// Close modal when clicking outside or on close buttons
$(document).ready(function() {
    // Click outside to close
    $('#modal-overlay').on('click', function(e) {
        if (e.target.id === 'modal-overlay') {
            // Find which modal is open and close it
            $('.modal[style*="display: block"]').each(function() {
                closeModal(this.id);
            });
        }
    });

    // Close button (×) click handler
    $(document).on('click', '.modal-close', function() {
        const modalId = $(this).data('modal');
        if (modalId) {
            closeModal(modalId);
        }
    });

    // Cancel button click handler
    $(document).on('click', '.modal-cancel', function() {
        const modalId = $(this).data('modal');
        if (modalId) {
            closeModal(modalId);
        }
    });
});

// Modal and action functions
function showAddAdminModal() {
    document.getElementById('new-admin-email').value = '';
    openModal('add-admin-modal');
}

// Event listener for Add Admin confirmation
$(document).ready(function() {
    $('#confirm-add-admin-btn').on('click', function() {
        const email = document.getElementById('new-admin-email').value.trim();
        if (!email) {
            showToast('Please enter an email', true);
            return;
        }

        secureFetch('/admin/admins/data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast('Admin added successfully');
                closeModal('add-admin-modal');
                if ($.fn.DataTable.isDataTable('#admins-table')) {
                    $('#admins-table').DataTable().ajax.reload();
                }
            } else {
                showToast(data.error || 'Failed to add admin', true);
            }
        });
    });

    // Event listener for Save Permissions
    $('#save-permissions-btn').on('click', savePermissions);

    // Event listener for Save App
    $('#save-app-btn').on('click', saveApp);

    // Event listener for Save API Key
    $('#save-api-key-btn').on('click', saveApiKey);

    // Copy newly created API key
    $('#copy-api-key-btn').on('click', function() {
        const input = document.getElementById('created-api-key');
        input.select();
        input.setSelectionRange(0, 99999);
        navigator.clipboard?.writeText(input.value).then(() => {
            showToast('Copied to clipboard');
        }).catch(() => {
            showToast('Copied', false);
        });
    });

    $('#app-access-add-email-btn').on('click', function() {
        const input = document.getElementById('app-access-email-input');
        const email = normalizeEmail(input.value);
        if (!email) {
            showToast('Enter an email to add', true);
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            showToast('Invalid email address', true);
            return;
        }
        addAccessEntry({
            principal_type: 'email',
            principal_ref: email,
            display_label: email,
        });
        input.value = '';
    });
    $('#app-access-email-input').on('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            $('#app-access-add-email-btn').trigger('click');
        }
    });

    $('#app-access-add-admins-btn').on('click', function() {
        addAccessEntry({
            principal_type: 'group_admins',
            principal_ref: 'all_admins',
            display_label: 'All admins',
        });
    });

    $('#app-access-add-event-btn').on('click', function() {
        const select = document.getElementById('app-access-event-select');
        const eventId = select.value;
        if (!eventId) {
            showToast('Select an event group first', true);
            return;
        }
        const selectedOption = select.options[select.selectedIndex];
        addAccessEntry({
            principal_type: 'group_event_attendees',
            principal_ref: eventId,
            display_label: `All attendees: ${selectedOption.textContent}`,
        });
    });

    $(document).on('click', '#app-access-chip-list button[data-access-index]', function() {
        const index = parseInt(this.dataset.accessIndex, 10);
        removeAccessEntryByIndex(index);
    });

    $('#app-allow-anyone').on('change', function() {
        renderAppAccessChips();
    });
});

function removeAdmin(email) {
    if (!confirm(`Remove admin privileges from ${email}?`)) return;

    secureFetch(`/admin/admins/data/${encodeURIComponent(email)}`, {
        method: 'DELETE',
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            showToast('Admin removed successfully');
            $('#admins-table').DataTable().ajax.reload();
        } else {
            showToast(data.error || 'Failed to remove admin', true);
        }
    });
}

function showPermissionsModal(email) {
    // Fetch current permissions
    secureFetch(`/admin/admins/${encodeURIComponent(email)}/permissions`)
        .then(r => r.json())
        .then(data => {
            if (!data.success) {
                showToast(data.error || 'Failed to load permissions', true);
                return;
            }

            const permissions = data.permissions || [];
            const content = document.getElementById('permissions-content');

            // Store email for later use
            content.dataset.adminEmail = email;

            // Build permissions UI
            let html = `<h3 class="mb-15">Permissions for ${email}</h3>`;

            // Universal permission - only write
            html += `<div class="permission-group">
                <h3>Universal</h3>
                <div class="permission-item">
                    <label class="permission-label">*</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-write" data-type="*" data-value="*"> Write</label>
                    </div>
                </div>
            </div>`;

            // Events section
            html += `<div class="permission-group">
                <h3>Events</h3>
                <div class="permission-item">
                    <label class="permission-label">All Events</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-read" data-type="event" data-value="*"> Read</label>
                        <label><input type="checkbox" class="access-write" data-type="event" data-value="*"> Write</label>
                    </div>
                </div>
                <div class="permission-item">
                    <label class="permission-label">Counterspell</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-read" data-type="event" data-value="counterspell"> Read</label>
                        <label><input type="checkbox" class="access-write" data-type="event" data-value="counterspell"> Write</label>
                    </div>
                </div>
                <div class="permission-item">
                    <label class="permission-label">Scrapyard</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-read" data-type="event" data-value="scrapyard"> Read</label>
                        <label><input type="checkbox" class="access-write" data-type="event" data-value="scrapyard"> Write</label>
                    </div>
                </div>
                <div class="permission-item">
                    <label class="permission-label">hack.sv 2025</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-read" data-type="event" data-value="hacksv_2025"> Read</label>
                        <label><input type="checkbox" class="access-write" data-type="event" data-value="hacksv_2025"> Write</label>
                    </div>
                </div>
            </div>`;

            // Pages section
            html += `<div class="permission-group">
                <h3>Pages</h3>`;

            const pages = ['attendees', 'events', 'keys', 'admins', 'apps'];
            pages.forEach(page => {
                html += `<div class="permission-item">
                    <label class="permission-label">${page.charAt(0).toUpperCase() + page.slice(1)}</label>
                    <div class="permission-access">
                        <label><input type="checkbox" class="access-read" data-type="page" data-value="${page}"> Read</label>
                        <label><input type="checkbox" class="access-write" data-type="page" data-value="${page}"> Write</label>
                    </div>
                </div>`;
            });

            html += `</div>`;

            // Legacy app permissions section (non-runtime)
            html += `<div class="permission-group">
                <h3>Apps (Legacy)</h3>
                <p class="text-small">Per-admin app permissions are retained for historical visibility only and are not used in runtime app access checks.</p>
                <div id="legacy-app-permissions"></div>
            </div>`;

            content.innerHTML = html;

            const legacyAppPerms = permissions.filter(perm => perm.permission_type === 'app');
            const legacyContainer = content.querySelector('#legacy-app-permissions');
            if (legacyAppPerms.length === 0) {
                legacyContainer.innerHTML = '<p class="muted">No legacy app permissions assigned.</p>';
            } else {
                legacyContainer.innerHTML = legacyAppPerms
                    .map(perm => `<span class="permission-pill">${perm.permission_value} (${perm.access_level})</span>`)
                    .join('');
            }

            // Check existing permissions for events and pages (before apps are loaded)
            permissions.forEach(perm => {
                if (perm.permission_type !== 'app') {
                    const checkbox = content.querySelector(`input[data-type="${perm.permission_type}"][data-value="${perm.permission_value}"].access-${perm.access_level}`);
                    if (checkbox) {
                        checkbox.checked = true;
                    }
                }
            });

            openModal('permissions-modal');
        });
}
function savePermissions() {
    const content = document.getElementById('permissions-content');
    const email = content.dataset.adminEmail;

    // Collect all checked permissions
    const permissions = [];
    content.querySelectorAll('.access-read:checked, .access-write:checked').forEach(checkbox => {
        permissions.push({
            permission_type: checkbox.dataset.type,
            permission_value: checkbox.dataset.value,
            access_level: checkbox.classList.contains('access-read') ? 'read' : 'write'
        });
    });

    // Send to server
    secureFetch(`/admin/admins/${encodeURIComponent(email)}/permissions`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ permissions })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            showToast('Permissions updated successfully');
            closeModal('permissions-modal');
        } else {
            showToast(data.error || 'Failed to update permissions', true);
        }
    });
}

function normalizeEmail(value) {
    return (value || '').trim().toLowerCase();
}

function renderAppAccessChips() {
    const list = document.getElementById('app-access-chip-list');
    if (!list) return;

    if (!appAccessEntries.length) {
        list.innerHTML = '<p class="muted">No access principals added.</p>';
    } else {
        list.innerHTML = appAccessEntries.map((entry, index) => {
            const isGroup = entry.principal_type !== 'email';
            const icon = isGroup ? 'group' : 'person';
            const label = isGroup ? entry.display_label : entry.principal_ref;
            const kindClass = isGroup ? 'access-chip-group' : 'access-chip-email';
            return `
                <span class="access-chip ${kindClass}">
                    <span class="material-icons">${icon}</span>
                    <span>${label}</span>
                    <button type="button" data-access-index="${index}" aria-label="Remove access principal">&times;</button>
                </span>
            `;
        }).join('');
    }

    const warning = document.getElementById('app-access-warning');
    if (!warning) return;
    const allowAnyone = document.getElementById('app-allow-anyone')?.checked;
    if (!allowAnyone && appAccessEntries.length === 0) {
        warning.classList.remove('hidden');
        warning.textContent = 'Restricted app with empty ACL: only universal-write admins can recover access.';
    } else {
        warning.classList.add('hidden');
        warning.textContent = '';
    }
}

function addAccessEntry(entry) {
    const exists = appAccessEntries.some(existing =>
        existing.principal_type === entry.principal_type &&
        existing.principal_ref === entry.principal_ref
    );
    if (exists) {
        showToast('Principal already added', true);
        return;
    }
    appAccessEntries.push(entry);
    renderAppAccessChips();
}

function removeAccessEntryByIndex(index) {
    appAccessEntries = appAccessEntries.filter((_, idx) => idx !== index);
    renderAppAccessChips();
}

async function ensureAppEventsCatalog() {
    if (appEventsCatalog.length) return appEventsCatalog;
    const response = await secureFetch('/static/events.json');
    const data = await response.json();
    appEventsCatalog = Object.entries(data)
        .filter(([eventId]) => !eventId.startsWith('_'))
        .map(([eventId, eventData]) => ({
            id: eventId,
            name: eventData.name || eventId
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
    return appEventsCatalog;
}

async function populateEventGroupSelect() {
    const eventSelect = document.getElementById('app-access-event-select');
    if (!eventSelect) return;

    try {
        const events = await ensureAppEventsCatalog();
        eventSelect.innerHTML = '<option value="">Select event group…</option>';
        events.forEach(eventItem => {
            const option = document.createElement('option');
            option.value = eventItem.id;
            option.textContent = `${eventItem.name} (${eventItem.id})`;
            eventSelect.appendChild(option);
        });
    } catch (error) {
        showToast('Failed to load event groups', true);
    }
}

function getAppAccessPayload() {
    return appAccessEntries.map(entry => ({
        principal_type: entry.principal_type,
        principal_ref: entry.principal_ref
    }));
}

async function saveAppAccessEntries(appId) {
    const response = await secureFetch(`/admin/apps/${appId}/access`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ entries: getAppAccessPayload() }),
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
        const reason = data.reason ? ` (${data.reason})` : '';
        throw new Error((data.error || 'Failed to save ACL entries') + reason);
    }
}

async function loadAppAccessEntries(appId) {
    const response = await secureFetch(`/admin/apps/${appId}/access`);
    const data = await response.json();
    if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to load app access entries');
    }

    appAccessEntries = (data.entries || []).map(entry => ({
        principal_type: entry.principal_type,
        principal_ref: entry.principal_ref,
        display_label: entry.display_label || entry.principal_ref,
    }));
    renderAppAccessChips();
}

function showAddAppModal() {
    document.getElementById('app-modal-title').textContent = 'Add OAuth 2.0 App';
    const subtitle = document.querySelector('#app-modal .app-modal-subtitle');
    if (subtitle) subtitle.textContent = 'Create a new OAuth app and define launch access before publishing.';
    const saveButton = document.getElementById('save-app-btn');
    if (saveButton) saveButton.textContent = 'Create App';
    document.getElementById('app-id').value = '';
    document.getElementById('app-name').value = '';
    document.getElementById('app-icon').value = '';
    document.getElementById('app-redirect-uris').value = '';
    document.getElementById('app-allow-anyone').checked = false;
    document.getElementById('app-skip-consent').checked = false;
    document.getElementById('app-access-email-input').value = '';
    appAccessEntries = [];
    renderAppAccessChips();
    populateEventGroupSelect();

    // Hide credentials section for new apps
    const credentials = document.getElementById('app-credentials');
    credentials.classList.add('hidden');

    // Load scopes
    loadAppScopes([]);

    openModal('app-modal');
}

function editApp(appId) {
    const app = appsCatalog.find(a => a.id === appId);
    if (!app) {
        showToast('App not found. Refreshing list...', true);
        refreshAppsCatalog();
        return;
    }

    document.getElementById('app-modal-title').textContent = 'Edit OAuth 2.0 App';
    const subtitle = document.querySelector('#app-modal .app-modal-subtitle');
    if (subtitle) subtitle.textContent = 'Update credentials, scopes, and access policies for this app.';
    const saveButton = document.getElementById('save-app-btn');
    if (saveButton) saveButton.textContent = 'Save Changes';
    document.getElementById('app-id').value = app.id;
    document.getElementById('app-name').value = app.name;
    document.getElementById('app-icon').value = app.icon || '';
    document.getElementById('app-redirect-uris').value = (app.redirect_uris_list || []).join('\n');
    document.getElementById('app-allow-anyone').checked = app.allow_anyone;
    document.getElementById('app-skip-consent').checked = app.skip_consent_screen || false;
    document.getElementById('app-access-email-input').value = '';

    const credentials = document.getElementById('app-credentials');
    if (app.client_id) {
        credentials.classList.remove('hidden');
        document.getElementById('app-client-id').value = app.client_id;
        document.getElementById('app-client-secret').value = app.client_secret || '';
        document.getElementById('app-client-secret').type = 'password';
    } else {
        credentials.classList.add('hidden');
    }

    loadAppScopes(app.allowed_scopes_list || []);
    populateEventGroupSelect()
        .then(() => loadAppAccessEntries(app.id))
        .then(() => openModal('app-modal'))
        .catch((error) => {
            showToast(`Failed to load app access: ${error.message}`, true);
        });
}

async function saveApp() {
    const appId = document.getElementById('app-id').value;
    const name = document.getElementById('app-name').value.trim();
    const icon = document.getElementById('app-icon').value.trim();
    const redirectUrisText = document.getElementById('app-redirect-uris').value.trim();
    const allowAnyone = document.getElementById('app-allow-anyone').checked;
    const skipConsent = document.getElementById('app-skip-consent').checked;

    if (!name) {
        showToast('Name is required', true);
        return;
    }

    // Parse redirect URIs
    const redirectUris = redirectUrisText.split('\n').map(uri => uri.trim()).filter(uri => uri.length > 0);
    if (redirectUris.length === 0) {
        showToast('At least one redirect URI is required', true);
        return;
    }

    // Get selected scopes
    const selectedScopes = [];
    document.querySelectorAll('#app-scopes input[type="checkbox"]:checked').forEach(cb => {
        selectedScopes.push(cb.value);
    });

    if (selectedScopes.length === 0) {
        showToast('At least one scope is required', true);
        return;
    }

    try {
        const method = appId ? 'PUT' : 'POST';
        const url = appId ? `/admin/apps/${appId}` : '/admin/apps';

        const appResponse = await secureFetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name,
                icon,
                redirect_uris: redirectUris,
                allowed_scopes: selectedScopes,
                allow_anyone: allowAnyone,
                skip_consent_screen: skipConsent
            })
        });
        if (appResponse.status === 403) {
            showToast(`You don't have permission to ${appId ? 'edit' : 'create'} apps`, true);
            return;
        }

        const appData = await appResponse.json();
        if (!appData.success) {
            showToast(appData.error || 'Failed to save app', true);
            return;
        }

        const targetAppId = appId || appData.app_id;
        await saveAppAccessEntries(targetAppId);

        showToast(appId ? 'App updated successfully' : 'App created successfully');
        closeModal('app-modal');
        await refreshAppsCatalog();
    } catch (error) {
        // Session expired and permission denied errors already shown
        if (error.message !== 'Session expired' &&
            error.message !== 'CSRF token is missing' &&
            error.message !== 'Permission denied') {
            showToast('Failed to save app: ' + error.message, true);
        }
    }
}

function deleteApp(appId) {
    if (!confirm('Delete this app?')) return;

    secureFetch(`/admin/apps/${appId}`, {
        method: 'DELETE',
    })
    .then(r => {
        if (r.status === 403) {
            showToast('You don\'t have permission to delete apps', true);
            throw new Error('Permission denied');
        }
        return r.json();
    })
    .then(data => {
        if (data.success) {
            showToast('App deleted successfully');
            refreshAppsCatalog();
        } else {
            showToast(data.error || 'Failed to delete app', true);
        }
    })
    .catch(error => {
        // Session expired and permission denied errors already shown
        if (error.message !== 'Session expired' &&
            error.message !== 'CSRF token is missing' &&
            error.message !== 'Permission denied') {
            showToast('Failed to delete app: ' + error.message, true);
        }
    });
}

// Load available scopes from static/scopes.json
function loadAppScopes(selectedScopes = []) {
    secureFetch('/static/scopes.json')
        .then(r => r.json())
        .then(data => {
            const scopesContainer = document.getElementById('app-scopes');
            scopesContainer.innerHTML = '';

            data.scopes.forEach(scope => {
                const isChecked = selectedScopes.includes(scope.name);
                const isRequired = scope.required;

                const scopeDiv = document.createElement('div');
                scopeDiv.className = 'scope-card';
                scopeDiv.innerHTML = `
                    <label>
                        <input type="checkbox"
                               value="${scope.name}"
                               ${isChecked ? 'checked' : ''}
                               ${isRequired ? 'disabled checked' : ''}>
                        <div>
                            <strong>${scope.name}${isRequired ? '<span class="scope-required-pill">Required</span>' : ''}</strong>
                            <small>${scope.description}</small>
                        </div>
                    </label>
                `;
                const checkbox = scopeDiv.querySelector('input[type="checkbox"]');
                if (checkbox?.checked) {
                    scopeDiv.classList.add('scope-card-selected');
                }
                if (checkbox) {
                    checkbox.addEventListener('change', () => {
                        scopeDiv.classList.toggle('scope-card-selected', checkbox.checked);
                    });
                }
                scopesContainer.appendChild(scopeDiv);
            });
        })
        .catch(err => {
            console.error('Failed to load scopes:', err);
            document.getElementById('app-scopes').innerHTML = '<p class="error">Failed to load scopes</p>';
        });
}

// Copy text to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.value;

    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Failed to copy to clipboard', true);
    });
}

// Toggle secret visibility
function toggleSecretVisibility(event) {
    const secretInput = document.getElementById('app-client-secret');
    const button = event ? event.target : null;

    if (secretInput.type === 'password') {
        secretInput.type = 'text';
        if (button) button.textContent = 'Hide';
    } else {
        secretInput.type = 'password';
        if (button) button.textContent = 'Show';
    }
}

// Regenerate client secret
function regenerateSecret() {
    const appId = document.getElementById('app-id').value;

    if (!appId) {
        showToast('Cannot regenerate secret for new app', true);
        return;
    }

    if (!confirm('Regenerate client secret? This will invalidate the current secret and break existing integrations until they update to the new secret.')) {
        return;
    }

    secureFetch(`/admin/apps/${appId}/regenerate-secret`, {
        method: 'POST',
    })
    .then(r => {
        if (r.status === 403) {
            showToast('You don\'t have permission to regenerate secrets', true);
            throw new Error('Permission denied');
        }
        return r.json();
    })
    .then(data => {
        if (data.success) {
            document.getElementById('app-client-secret').value = data.client_secret;
            document.getElementById('app-client-secret').type = 'text';
            showToast('Client secret regenerated successfully');
        } else {
            showToast(data.error || 'Failed to regenerate secret', true);
        }
    })
    .catch(error => {
        // Session expired and permission denied errors already shown
        if (error.message !== 'Session expired' &&
            error.message !== 'CSRF token is missing' &&
            error.message !== 'Permission denied') {
            showToast('Failed to regenerate secret: ' + error.message, true);
        }
    });
}
