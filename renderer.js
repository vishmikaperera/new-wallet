// Renderer process
const { ipcRenderer } = require('electron');

// Debug logging
function debug(msg) {
    console.log(`[DEBUG] ${msg}`);
}

class PasswordWallet {
    constructor() {
        debug('Initializing PasswordWallet');
        this.currentScreen = 'auth';
        this.passwords = [];
        this.currentUser = null;
        this.masterKey = null;
        this.charts = {};
        this.defaultMasterPassword = 'test123'; // Default master password for testing
        
        this.initializeApp();
    }

    async initializeApp() {
        debug('Starting app initialization');
        try {
            this.initializeUI();
            this.setupEventListeners();
            await this.checkBiometricAvailability();
            this.setupModernEffects();
            this.init3DBackground();
            this.initParticles();
            
            // Set default master password hint
            const passwordInput = document.getElementById('master-password');
            if (passwordInput) {
                passwordInput.placeholder = 'Default password: test123';
            }
            debug('App initialization complete');
        } catch (error) {
            console.error('Error initializing app:', error);
        }
    }

    setupModernEffects() {
        // Add interactive effects to cards
        document.querySelectorAll('.password-item').forEach(card => {
            card.classList.add('interactive-card', 'rainbow-border');
            this.setupMagneticEffect(card);
            this.setupColorShift(card);
        });

        // Add liquid effect to buttons
        document.querySelectorAll('.primary-button').forEach(button => {
            button.classList.add('liquid-button');
            this.setupMagneticEffect(button);
        });

        // Add prismatic effect to headings
        document.querySelectorAll('h1, h2').forEach(heading => {
            heading.classList.add('prismatic-text');
        });

        // Add aurora effect to main content
        document.querySelector('.main-content').classList.add('aurora-bg');

        // Add interactive hover effects
        document.querySelectorAll('.interactive').forEach(element => {
            element.addEventListener('mousemove', this.handleHoverEffect);
            element.addEventListener('mouseleave', this.removeHoverEffect);
            this.setupMagneticEffect(element);
        });

        // Add gradient text effect to headings
        document.querySelectorAll('h1, h2, h3').forEach(heading => {
            heading.classList.add('gradient-text');
        });

        // Add floating label effect to inputs
        document.querySelectorAll('.form-group').forEach(group => {
            const input = group.querySelector('input');
            const label = group.querySelector('label');
            if (input && label) {
                group.classList.add('float-label');
            }
        });

        // Add 3D effect to buttons
        document.querySelectorAll('button').forEach(button => {
            button.classList.add('button-3d');
            this.addRippleEffect(button);
        });

        // Initialize the modern toast system
        this.initializeToastSystem();
    }

    handleHoverEffect(e) {
        const bounds = e.target.getBoundingClientRect();
        const x = e.clientX - bounds.left;
        const y = e.clientY - bounds.top;
        
        e.target.style.setProperty('--mouse-x', `${x}px`);
        e.target.style.setProperty('--mouse-y', `${y}px`);
        
        const shine = e.target.querySelector('.shine') || document.createElement('div');
        shine.className = 'shine';
        shine.style.left = `${x}px`;
        shine.style.top = `${y}px`;
        
        if (!e.target.contains(shine)) {
            e.target.appendChild(shine);
        }
    }

    removeHoverEffect(e) {
        const shine = e.target.querySelector('.shine');
        if (shine) {
            shine.remove();
        }
    }

    init3DBackground() {
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ canvas: document.getElementById('bgCanvas'), alpha: true });
        
        renderer.setSize(window.innerWidth, window.innerHeight);
        camera.position.z = 5;

        // Create animated floating cubes
        const cubes = [];
        for (let i = 0; i < 20; i++) {
            const geometry = new THREE.BoxGeometry();
            const material = new THREE.MeshBasicMaterial({ 
                color: 0x3B82F6,
                opacity: 0.1,
                transparent: true
            });
            const cube = new THREE.Mesh(geometry, material);
            
            cube.position.x = Math.random() * 20 - 10;
            cube.position.y = Math.random() * 20 - 10;
            cube.position.z = Math.random() * 20 - 10;
            
            scene.add(cube);
            cubes.push(cube);

            // Animate each cube
            gsap.to(cube.rotation, {
                x: Math.PI * 2,
                y: Math.PI * 2,
                duration: 10 + Math.random() * 5,
                repeat: -1,
                ease: "none"
            });
        }

        const animate = () => {
            requestAnimationFrame(animate);
            renderer.render(scene, camera);
        };
        animate();

        // Handle window resize
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    }

    initParticles() {
        particlesJS("particles-js", {
            particles: {
                number: { value: 80, density: { enable: true, value_area: 800 } },
                color: { value: "#3B82F6" },
                shape: { type: "circle" },
                opacity: {
                    value: 0.5,
                    random: false,
                    animation: { enable: true, speed: 1, minimumValue: 0.1, sync: false }
                },
                size: {
                    value: 3,
                    random: true,
                    animation: { enable: true, speed: 2, minimumValue: 0.1, sync: false }
                },
                lineLinked: {
                    enable: true,
                    distance: 150,
                    color: "#3B82F6",
                    opacity: 0.4,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 2,
                    direction: "none",
                    random: false,
                    straight: false,
                    outMode: "out",
                    bounce: false
                }
            },
            interactivity: {
                detectOn: "canvas",
                events: {
                    onHover: { enable: true, mode: "repulse" },
                    onClick: { enable: true, mode: "push" },
                    resize: true
                }
            },
            retina_detect: true
        });
    }

    initCharts(stats) {
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        this.charts.category = new Chart(categoryCtx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(stats.byCategory),
                datasets: [{
                    data: Object.values(stats.byCategory),
                    backgroundColor: [
                        '#3B82F6',
                        '#60A5FA',
                        '#93C5FD',
                        '#BFDBFE',
                        '#2563EB'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'white'
                        }
                    }
                }
            }
        });
    }

    async loadPasswords() {
        try {
            const result = await ipcRenderer.invoke('get-passwords', { 
                userId: this.currentUser,
                masterKey: this.masterKey
            });

            if (result.success) {
                this.passwords = result.passwords;
                this.displayPasswords();
                
                const stats = await ipcRenderer.invoke('get-password-stats', { 
                    userId: this.currentUser 
                });
                if (stats.success) {
                    this.initCharts(stats.stats);
                }
            }
        } catch (error) {
            this.showError('Error loading passwords: ' + error.message);
        }
    }

    displayPasswords() {
        const container = document.getElementById('passwordListView');
        container.innerHTML = '';

        this.passwords.forEach(password => {
            const card = document.createElement('div');
            card.className = 'password-card';
            card.innerHTML = `
                <h3 class="text-xl font-bold mb-2">${password.title}</h3>
                <p class="text-gray-400 mb-2">${password.username}</p>
                <div class="flex justify-between items-center">
                    <button class="btn-primary copy-btn" data-id="${password.id}">
                        Copy Password
                    </button>
                    <button class="text-gray-400 hover:text-white edit-btn" data-id="${password.id}">
                        Edit
                    </button>
                </div>
            `;
            
            // Add modern effects
            card.classList.add('interactive-card', 'rainbow-border');
            this.setupMagneticEffect(card);
            this.setupColorShift(card);
            
            container.appendChild(card);
        });
    }

    setupMagneticEffect(element) {
        const strength = 15;
        
        element.addEventListener('mousemove', (e) => {
            const rect = element.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            const deltaX = e.clientX - centerX;
            const deltaY = e.clientY - centerY;
            
            const percentX = deltaX / (rect.width / 2);
            const percentY = deltaY / (rect.height / 2);
            
            const transform = `translate(${percentX * strength}px, ${percentY * strength}px) rotate(${percentX * 5}deg)`;
            element.style.transform = transform;
        });

        element.addEventListener('mouseleave', () => {
            element.style.transform = 'translate(0, 0) rotate(0deg)';
        });
    }

    setupColorShift(element) {
        let hue = 0;
        let isHovered = false;

        element.addEventListener('mouseenter', () => {
            isHovered = true;
            this.animateHue(element, hue);
        });

        element.addEventListener('mouseleave', () => {
            isHovered = false;
        });
    }

    animateHue(element, hue) {
        hue = (hue + 1) % 360;
        element.style.filter = `hue-rotate(${hue}deg)`;
        if (element.classList.contains('hover')) {
            requestAnimationFrame(() => this.animateHue(element, hue));
        }
    }

    showSuccessAnimation(element) {
        element.classList.add('success-animation', 'active');
        setTimeout(() => {
            element.classList.remove('success-animation', 'active');
        }, 2000);
    }

    updatePasswordStrength(password) {
        const strengthIndicator = document.querySelector('.strength-indicator');
        if (!strengthIndicator) return;

        const strength = this.calculatePasswordStrength(password);
        strengthIndicator.style.setProperty('--strength', `${strength}%`);
        
        // Add color effect based on strength
        if (strength < 33) {
            strengthIndicator.classList.add('weak');
            strengthIndicator.classList.remove('medium', 'strong');
        } else if (strength < 66) {
            strengthIndicator.classList.add('medium');
            strengthIndicator.classList.remove('weak', 'strong');
        } else {
            strengthIndicator.classList.add('strong');
            strengthIndicator.classList.remove('weak', 'medium');
        }
    }

    addRippleEffect(element) {
        element.addEventListener('click', e => {
            const bounds = element.getBoundingClientRect();
            const x = e.clientX - bounds.left;
            const y = e.clientY - bounds.top;

            const ripple = document.createElement('div');
            ripple.className = 'ripple';
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;

            element.appendChild(ripple);
            setTimeout(() => ripple.remove(), 1000);
        });
    }

    initializeToastSystem() {
        this.toastContainer = document.createElement('div');
        this.toastContainer.className = 'toast-container';
        document.body.appendChild(this.toastContainer);
    }

    async initializeUI() {
        this.screens = {
            auth: document.getElementById('auth-screen'),
            passwords: document.getElementById('passwords-screen'),
            passwordDetail: document.getElementById('password-detail-screen'),
            settings: document.getElementById('settings-screen')
        };

        // Initialize dark mode from settings
        this.updateTheme();
    }

    async checkBiometricAvailability() {
        const isAvailable = await ipcRenderer.invoke('checkBiometricAvailability');
        const biometricButton = document.getElementById('biometric-button');
        if (!isAvailable) {
            biometricButton.style.display = 'none';
        }
    }

    setupEventListeners() {
        // Authentication
        const unlockBtn = document.getElementById('unlock-btn');
        if (unlockBtn) {
            unlockBtn.addEventListener('click', () => this.authenticateWithPassword());
        }

        // Handle enter key on master password input
        const masterPasswordInput = document.getElementById('master-password');
        if (masterPasswordInput) {
            masterPasswordInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.authenticateWithPassword();
                }
            });
        }

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.handleNavigation(view);
                
                // Update active state
                document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
                e.currentTarget.classList.add('active');
            });
        });

        // Password Management
        const addNewBtn = document.getElementById('add-new');
        if (addNewBtn) {
            addNewBtn.addEventListener('click', () => this.showPasswordDetail());
        }

        const generatePasswordBtn = document.getElementById('generate-password');
        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', () => this.generatePassword());
        }

        const showPasswordBtn = document.getElementById('show-password');
        if (showPasswordBtn) {
            showPasswordBtn.addEventListener('click', () => this.togglePasswordVisibility());
        }

        const savePasswordBtn = document.getElementById('save-password');
        if (savePasswordBtn) {
            savePasswordBtn.addEventListener('click', () => this.savePassword());
        }

        // Back button in password detail screen
        const backButton = document.querySelector('.back-button');
        if (backButton) {
            backButton.addEventListener('click', () => this.showScreen('passwords'));
        }

        // Delete button in password detail screen
        const deleteButton = document.querySelector('.delete-button');
        if (deleteButton) {
            deleteButton.addEventListener('click', () => this.deleteCurrentPassword());
        }

        // Search
        document.getElementById('search').addEventListener('input', (e) => this.handleSearch(e.target.value));

        // Settings
        document.getElementById('dark-mode').addEventListener('change', (e) => this.toggleDarkMode(e.target.checked));
        document.getElementById('export-data').addEventListener('click', () => this.exportPasswords());
        document.getElementById('import-data').addEventListener('click', () => this.importPasswords());
    }

    async authenticateWithBiometric() {
        try {
            const success = await ipcRenderer.invoke('authenticateWithBiometric');
            if (success) {
                await this.loadPasswords();
                this.showScreen('passwords');
            }
        } catch (error) {
            this.showError('Biometric authentication failed');
        }
    }

    async authenticateWithPassword() {
        debug('Attempting password authentication');
        const passwordInput = document.getElementById('master-password');
        if (!passwordInput) {
            console.error('Password input not found');
            return;
        }

        const password = passwordInput.value;
        if (!password) {
            this.showError('Please enter master password');
            return;
        }

        try {
            debug('Checking password...');
            // For testing, allow the default password
            if (password === this.defaultMasterPassword) {
                debug('Using default password');
                await this.loadPasswords();
                this.showScreen('passwords');
                this.showSuccess('Logged in with default password');
                return;
            }

            const success = await ipcRenderer.invoke('authenticate', { password });
            if (success) {
                debug('Authentication successful');
                await this.loadPasswords();
                this.showScreen('passwords');
                this.showSuccess('Successfully logged in');
            } else {
                debug('Invalid password');
                this.showError('Invalid password');
            }
        } catch (error) {
            console.error('Authentication error:', error);
            this.showError('Authentication failed');
        }
    }

    async loadPasswords() {
        try {
            this.passwords = await ipcRenderer.invoke('getPasswords');
            this.renderPasswordsList();
        } catch (error) {
            this.showError('Failed to load passwords');
        }
    }

    renderPasswordsList(filteredPasswords = null) {
        const list = document.getElementById('passwords-list');
        list.innerHTML = '';

        const passwords = filteredPasswords || this.passwords;
        passwords.forEach(pwd => {
            const item = document.createElement('div');
            item.className = 'password-item';
            item.innerHTML = `
                <div class="item-icon">
                    <img src="https://favicon.ico/${pwd.url}" onerror="this.src='assets/default-icon.png'">
                </div>
                <div class="item-details">
                    <h3>${pwd.title}</h3>
                    <p>${pwd.username}</p>
                </div>
                ${pwd.otp_secret ? '<span class="otp-badge">2FA</span>' : ''}
            `;
            item.addEventListener('click', () => this.showPasswordDetail(pwd));
            list.appendChild(item);
        });
    }

    handleSearch(query) {
        const filtered = this.passwords.filter(pwd => 
            pwd.title.toLowerCase().includes(query.toLowerCase()) ||
            pwd.username.toLowerCase().includes(query.toLowerCase())
        );
        this.renderPasswordsList(filtered);
    }

    showPasswordDetail(password = null) {
        this.showScreen('passwordDetail');
        if (password) {
            // Edit mode
            document.getElementById('title').value = password.title;
            document.getElementById('username').value = password.username;
            document.getElementById('password').value = password.password;
            document.getElementById('url').value = password.url;
            document.getElementById('category').value = password.category;
            document.getElementById('enable-otp').checked = !!password.otp_secret;
            if (password.otp_secret) {
                document.getElementById('otp-secret').value = password.otp_secret;
                this.updateOTPDisplay(password.otp_secret);
            }
        } else {
            // Add mode
            document.getElementById('title').value = '';
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('url').value = '';
            document.getElementById('category').value = 'login';
            document.getElementById('enable-otp').checked = false;
            document.getElementById('otp-secret').value = '';
        }
    }

    async savePassword() {
        const passwordData = {
            title: document.getElementById('title').value,
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
            url: document.getElementById('url').value,
            category: document.getElementById('category').value,
            otpSecret: document.getElementById('enable-otp').checked ? 
                      document.getElementById('otp-secret').value : null
        };

        try {
            await ipcRenderer.invoke('addPassword', passwordData);
            await this.loadPasswords();
            this.showScreen('passwords');
        } catch (error) {
            this.showError('Failed to save password');
        }
    }

    generatePassword() {
        const length = 16;
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        document.getElementById('password').value = password;
    }

    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleBtn = document.getElementById('show-password');
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            passwordInput.type = 'password';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }

    async updateOTPDisplay(secret) {
        if (!secret) return;
        try {
            const otp = await ipcRenderer.invoke('generateOTP', secret);
            document.getElementById('current-otp').textContent = otp;
            setTimeout(() => this.updateOTPDisplay(secret), 1000);
        } catch (error) {
            console.error('Failed to generate OTP:', error);
        }
    }

    showScreen(screenName) {
        const screens = {
            'auth': document.getElementById('auth-screen'),
            'passwords': document.getElementById('passwords-screen'),
            'passwordDetail': document.getElementById('password-detail-screen'),
            'settings': document.getElementById('settings-screen')
        };

        // Hide all screens
        Object.values(screens).forEach(screen => {
            if (screen) screen.classList.add('hidden');
        });

        // Show requested screen
        const screenToShow = screens[screenName];
        if (screenToShow) {
            screenToShow.classList.remove('hidden');
            this.currentScreen = screenName;

            // Special handling for passwords screen
            if (screenName === 'passwords') {
                this.renderPasswordsList();
            }
        }
    }

    updateTheme() {
        const darkMode = localStorage.getItem('darkMode') === 'true';
        document.body.classList.toggle('dark-theme', darkMode);
        document.getElementById('dark-mode').checked = darkMode;
    }

    toggleDarkMode(enabled) {
        localStorage.setItem('darkMode', enabled);
        this.updateTheme();
    }

    async exportPasswords() {
        try {
            const data = await ipcRenderer.invoke('exportPasswords');
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `password-wallet-export-${new Date().toISOString()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            this.showError('Failed to export passwords');
        }
    }

    async importPasswords() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        input.onchange = async (e) => {
            try {
                const file = e.target.files[0];
                const reader = new FileReader();
                reader.onload = async (event) => {
                    const data = JSON.parse(event.target.result);
                    await ipcRenderer.invoke('importPasswords', data);
                    await this.loadPasswords();
                };
                reader.readAsText(file);
            } catch (error) {
                this.showError('Failed to import passwords');
            }
        };
        input.click();
    }

    showError(message) {
        this.showToast(message, 'error');
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'check-circle'}"></i>
            <span>${message}</span>
        `;
        document.body.appendChild(toast);

        // Trigger reflow for animation
        toast.offsetHeight;
        toast.classList.add('show');

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    addModernEffects() {
        // Add hover effect to password items
        document.querySelectorAll('.password-item').forEach(item => {
            item.addEventListener('mouseenter', (e) => {
                const rect = item.getBoundingClientRect();
                item.style.transform = 'scale(1.02) translateY(-4px)';
            });

            item.addEventListener('mouseleave', () => {
                item.style.transform = 'none';
            });
        });

        // Add ripple effect to buttons
        document.querySelectorAll('button').forEach(button => {
            button.addEventListener('click', (e) => {
                const ripple = document.createElement('div');
                ripple.className = 'ripple';
                button.appendChild(ripple);

                const rect = button.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;

                ripple.style.width = ripple.style.height = `${size}px`;
                ripple.style.left = `${x}px`;
                ripple.style.top = `${y}px`;

                setTimeout(() => ripple.remove(), 1000);
            });
        });

        // Add smooth scroll to password list
        const passwordsList = document.querySelector('.passwords-list');
        if (passwordsList) {
            passwordsList.style.scrollBehavior = 'smooth';
        }

        // Add password strength indicator
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.updatePasswordStrength(e.target.value);
            });
        }
    }

    updatePasswordStrength(password) {
        const strengthIndicator = document.querySelector('.strength-bar');
        if (!strengthIndicator) return;

        const strength = this.calculatePasswordStrength(password);
        strengthIndicator.className = 'strength-bar';
        
        if (strength > 80) {
            strengthIndicator.classList.add('strong');
        } else if (strength > 50) {
            strengthIndicator.classList.add('medium');
        } else {
            strengthIndicator.classList.add('weak');
        }
    }

    calculatePasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength += 20;
        if (password.match(/[a-z]/)) strength += 20;
        if (password.match(/[A-Z]/)) strength += 20;
        if (password.match(/[0-9]/)) strength += 20;
        if (password.match(/[^a-zA-Z0-9]/)) strength += 20;
        return strength;
    }
}

// Create an instance of PasswordWallet
new PasswordWallet();
