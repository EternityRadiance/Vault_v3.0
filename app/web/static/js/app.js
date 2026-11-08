(function () {
    function getTheme() {
        const m = document.cookie.match(/(?:^|;\s*)theme=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : 'light';
    }

    function setTheme(value) {
        document.cookie = `theme=${value}; Path=/; Max-Age=31536000; SameSite=Lax`;
        document.documentElement.setAttribute('data-theme', value);
    }

    document.addEventListener('DOMContentLoaded', function () {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;
        btn.addEventListener('click', function () {
            const next = getTheme() === 'dark' ? 'light' : 'dark';
            setTheme(next);
        });
    });
})();