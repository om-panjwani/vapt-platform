document.addEventListener('DOMContentLoaded', () => {
    // Initialize elements
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const searchBox = document.querySelector('.search-box input');
    const newProjectBtn = document.getElementById('newProjectBtn');

    // Initialize modals
    initModals();

    // Initialize sidebar toggle
    initSidebarToggle();

    // Initialize sidebar collapse on resize
    initSidebarResize();

    // Initialize global search
    initGlobalSearch();

    // Initialize stats grid
    initStatsGrid();

    // Initialize dashboard tabs
    initDashboardTabs();

    // Initialize modals
    function initModals() {
        // Open create project modal
        newProjectBtn.addEventListener('click', () => {
            document.getElementById('createProjectModal').classList.add('active');
        });

        // Open create target modal
        document.getElementById('newTargetBtn').addEventListener('click', () => {
            document.getElementById('createTargetModal').classList.add('active');
        });

        // Open create scan modal
        document.getElementById('newScanBtn').addEventListener('click', () => {
            document.getElementById('createScanModal').classList.add('active');
        });

        // Open generate report modal
        document.getElementById('generateReportBtn').addEventListener('click', () => {
            document.getElementById('generateReportModal').classList.add('active');
        });

        // Close modals
        document.querySelectorAll('.modal-close, .btn-secondary, #createProjectCancel, #createTargetCancel, #createScanCancel, #generateReportCancel').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelector('.modal.active').classList.remove('active');
            });
        });

        // Close on overlay click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });

        // Form submissions
        document.getElementById('createProjectForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const name = document.getElementById('projectName').value.trim();
            if (name) {
                document.getElementById('createProjectModal').classList.remove('active');
                alert(`Project "${name}" created successfully!`);
            }
        });

        document.getElementById('createTargetForm').addEventListener('submit', (e) => {
            e.preventDefault();
            document.getElementById('createTargetModal').classList.remove('active');
            alert('Target added successfully!');
        });

        document.getElementById('createScanForm').addEventListener('submit', (e) => {
            e.preventDefault();
            document.getElementById('createScanModal').classList.remove('active');
            alert('Scan created successfully!');
        });

        document.getElementById('generateReportForm').addEventListener('submit', (e) => {
            e.preventDefault();
            document.getElementById('generateReportModal').classList.remove('active');
            alert('Report generation started!');
        });
    }

    // Sidebar toggle
    function initSidebarToggle() {
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('open');
                mainContent.classList.toggle('sidebar-open');
            });
        }
    }

    // Sidebar resize on window resize
    function initSidebarResize() {
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                if (window.innerWidth < 1025) {
                    sidebar.style.transform = 'translateX(-100%)';
                    mainContent.classList.remove('sidebar-open');
                }
            }, 100);
        });
    }

    // Global search
    function initGlobalSearch() {
        if (searchBox) {
            let searchTimeout;
            searchBox.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    const query = searchBox.value.trim().toLowerCase();
                    filterContent(query);
                }, 500);
            });
        }
    }

    function filterContent(query) {
        const pages = document.querySelectorAll('.page');
        const navItems = document.querySelectorAll('.nav-item');

        pages.forEach(page => {
            const text = page.textContent.toLowerCase();
            if (query) {
                page.style.display = text.includes(query) ? 'block' : 'none';
            } else {
                page.style.display = 'block';
            }
        });

        navItems.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(query) ? 'flex' : 'none';
        });
    }

    // Stats grid initialization - fetch from API
    async function initStatsGrid() {
        try {
            const response = await fetch('/api/v1/projects');
            if (response.ok) {
                const projects = await response.json();
                renderStatsGrid(projects.length);
            }
        } catch (e) {
            renderStatsGrid(0);
        }
    }

    function renderStatsGrid(totalProjects) {
        const statsGrid = document.getElementById('statsGrid');
        if (!statsGrid) return;

        const stats = [
            { label: 'Projects', value: totalProjects, icon: 'project' },
            { label: 'Hosts', value: 0, icon: 'host' },
            { label: 'Open Ports', value: 0, icon: 'port' },
            { label: 'Findings', value: 0, icon: 'finding' }
        ];

        statsGrid.innerHTML = stats.map(stat => `
            <div class="stat-card">
                <div class="stat-header">
                    <div class="stat-icon ${stat.icon}">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            ${getStatIconSvg(stat.icon)}
                        </svg>
                    </div>
                </div>
                <div class="stat-content">
                    <div class="stat-value">${stat.value}</div>
                    <div class="stat-label">${stat.label}</div>
                </div>
            </div>
        `).join('');
    }

    function getStatIconSvg(icon) {
        const icons = {
            project: `<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>`,
            host: `<circle cx="12" cy="12" r="10"/><path d="M8 14l7-5 7 5-3 2-9-7-9 7-3-2z"/>`,
            port: `<rect x="3" y="6" width="18" height="12" rx="2"/><circle cx="8.5" cy="13.5" r="1.5"/><circle cx="15.5" cy="13.5" r="1.5"/>`,
            finding: `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
            scan: `<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>`,
            report: `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>`,
            severity: `<rect x="3" y="4" width="5" height="7" rx="1"/><rect x="12" y="4" width="5" height="7" rx="1"/><rect x=21 y="4" width="5" height="7" rx="1"/>`
        };
        return icons[icon] || icons.project;
    }

    // Dashboard tabs initialization
    function initDashboardTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

                btn.classList.add('active');
                document.getElementById(btn.dataset.tab + 'Panel').classList.add('active');
            });
        });
    }
});