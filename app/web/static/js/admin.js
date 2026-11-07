(function () {
    function setText(id, value) {
        const el = document.querySelector(`#${id} div`);
        if (el) el.textContent = String(value);
    }

    async function refreshStats() {
        try {
            const resp = await fetch('/web/admin/stats', {
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' },
            });
            if (!resp.ok) return;
            const data = await resp.json();
            setText('stat-users', data.users);
            setText('stat-clients', data.clients);
            setText('stat-sessions', data.active_sessions);
            setText('stat-events', data.events_24h);
        } catch (e) {
            // Тихо игнорируем сетевые ошибки.
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // На дашборде есть контейнер — иначе выходим.
        if (!document.getElementById('stats-container')) return;
        setInterval(refreshStats, 30000);
    });
})();