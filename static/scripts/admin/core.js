// Admin Panel Core JavaScript

// Global variables
let currentSort = { column: null, direction: null };
let columnFilters = {};
let allRows = [];

// Events data - will be populated from server
let eventsData = {};

// Initialize
document.addEventListener("DOMContentLoaded", function () {
    allRows = Array.from(document.querySelectorAll(".user-row"));
    initializeFilters();
    setupKeyboardShortcuts();
    updateCount();

    // Add global search listener
    const searchInput = document.getElementById("globalSearch");
    if (searchInput) {
        searchInput.addEventListener("input", globalSearch);
    }
});

// Keyboard shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener("keydown", function (e) {
        if ((e.metaKey || e.ctrlKey) && e.key === "k") {
            e.preventDefault();
            document.getElementById("globalSearch").focus();
        }

        if (e.key === "Escape") {
            clearSearch();
            if (window.editingUser) window.cancelEdit();
        }

        // Tab navigation in edit mode
        if (e.key === "Tab" && window.editingUser) {
            // Special handling for events field checkboxes
            const activeElement = document.activeElement;
            if (activeElement && activeElement.type === "checkbox") {
                const eventsCell = activeElement.closest(
                    '[data-field="events"]'
                );
                if (eventsCell) {
                    const checkboxes = eventsCell.querySelectorAll(
                        'input[type="checkbox"]'
                    );
                    const currentIndex =
                        Array.from(checkboxes).indexOf(activeElement);

                    if (!e.shiftKey && currentIndex < checkboxes.length - 1) {
                        // Tab forward within checkboxes
                        e.preventDefault();
                        checkboxes[currentIndex + 1].focus();
                        return;
                    } else if (e.shiftKey && currentIndex > 0) {
                        // Tab backward within checkboxes
                        e.preventDefault();
                        checkboxes[currentIndex - 1].focus();
                        return;
                    }
                    // If at first/last checkbox, fall through to normal tab navigation
                }
            }

            e.preventDefault();
            const direction = e.shiftKey ? "backward" : "forward";
            if (window.handleTabNavigation) {
                window.handleTabNavigation(direction);
            }
        }
    });

    // Auto-save on Enter - now works globally when in edit mode
    document.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            // If in edit mode, always save regardless of focus
            if (window.editingUser) {
                e.preventDefault();
                window.saveUser(window.editingUser);
                return;
            }

            // If in search box, enter edit mode for first visible result
            if (e.target.id === "globalSearch") {
                e.preventDefault();
                enterEditModeForFirstResult();
                return;
            }
        }
    });

    // Auto-save on blur (only when clicking outside the current row)
    document.addEventListener(
        "blur",
        function (e) {
            if (
                e.target.classList.contains("edit-input") &&
                window.editingUser &&
                !window.justEnteredEditMode
            ) {
                // Add a delay to check if the new focus is outside the current row
                setTimeout(() => {
                    // Only save if we're still in edit mode and the new focus is outside the current row
                    if (
                        window.editingUser &&
                        document.contains(e.target) &&
                        !window.justEnteredEditMode
                    ) {
                        const currentRow = document.querySelector(
                            `[data-user-id="${window.editingUser}"]`
                        );
                        const newFocusElement = document.activeElement;

                        // Only save if the new focus is outside the current row
                        if (
                            !currentRow ||
                            !currentRow.contains(newFocusElement)
                        ) {
                            window.saveUser(window.editingUser);
                        }
                    }
                }, 100);
            }
        },
        true
    );
}

// Global search
function globalSearch() {
    const searchTerm = document
        .getElementById("globalSearch")
        .value.toLowerCase();
    let visibleCount = 0;

    allRows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        const matches = text.includes(searchTerm);
        row.style.display = matches ? "" : "none";
        if (matches) visibleCount++;
    });

    updateCount(visibleCount);
}

// Clear search
function clearSearch() {
    document.getElementById("globalSearch").value = "";
    allRows.forEach((row) => (row.style.display = ""));
    updateCount();
}

// Update count
function updateCount(count = null) {
    const total = count !== null ? count : allRows.length;
    document.getElementById("searchCount").textContent = `${total} entries`;
}

// Toggle filter
function toggleFilter(column) {
    const filterRow = document.getElementById("filterRow");
    const header = document.querySelector(`th[data-column="${column}"]`);

    // Toggle filter row visibility
    if (filterRow.classList.contains("show")) {
        filterRow.classList.remove("show");
        document
            .querySelectorAll("th")
            .forEach((th) => th.classList.remove("filter-expanded"));
    } else {
        filterRow.classList.add("show");
        header.classList.add("filter-expanded");
    }
}

// Apply column filter
function applyColumnFilter(column, value) {
    columnFilters[column] = value.toLowerCase();
    applyAllFilters();
}

// Apply date range filter
function applyDateRangeFilter() {
    const fromDate = document.getElementById("dob-from").value;
    const toDate = document.getElementById("dob-to").value;
    columnFilters["dob"] = { from: fromDate, to: toDate };
    applyAllFilters();
}

// Apply all filters
function applyAllFilters() {
    let visibleCount = 0;

    allRows.forEach((row) => {
        let show = true;

        // Apply global search first
        const globalTerm = document
            .getElementById("globalSearch")
            .value.toLowerCase();
        if (globalTerm && !row.textContent.toLowerCase().includes(globalTerm)) {
            show = false;
        }

        // Apply column filters
        for (const [column, filter] of Object.entries(columnFilters)) {
            if (!filter || !show) continue;

            if (column === "dob" && (filter.from || filter.to)) {
                const dobValue = row.dataset.dob;
                if (dobValue && dobValue !== "N/A") {
                    const dobDate = new Date(dobValue);
                    if (filter.from && dobDate < new Date(filter.from))
                        show = false;
                    if (filter.to && dobDate > new Date(filter.to))
                        show = false;
                }
            } else if (typeof filter === "string") {
                const cellValue = getCellValue(row, column).toLowerCase();
                if (!cellValue.includes(filter)) show = false;
            }
        }

        row.style.display = show ? "" : "none";
        if (show) visibleCount++;
    });

    updateCount(visibleCount);
}

// Get cell value
function getCellValue(row, column) {
    const cell = row.querySelector(`[data-field="${column}"]`);
    if (!cell) return "";

    if (column === "events") return row.dataset.events || "";
    if (column === "dietary") return row.dataset.dietary || "";
    if (column === "emergency_contact")
        return row.dataset.emergencyContact || "";

    return cell.textContent.trim();
}

// Enter edit mode for first visible result
function enterEditModeForFirstResult() {
    // Find first visible user row
    const visibleRows = allRows.filter((row) => row.style.display !== "none");

    if (visibleRows.length > 0) {
        const firstRow = visibleRows[0];
        const userEmail = firstRow.dataset.userId;

        if (userEmail && window.editUser) {
            // Enter edit mode
            window.editUser(userEmail);

            // Focus on email field (first field) after a short delay
            setTimeout(() => {
                focusEmailField(userEmail);
            }, 150);
        }
    }
}

// Focus on email field (first field) for a user in edit mode
function focusEmailField(userEmail) {
    const row = document.querySelector(`[data-user-id="${userEmail}"]`);
    if (row) {
        const emailCell = row.querySelector('[data-field="email"]');
        if (emailCell) {
            const input = emailCell.querySelector(".edit-input");
            if (input) {
                input.focus();
            }
        }
    }
}

// Add global search listener (moved to DOMContentLoaded)
