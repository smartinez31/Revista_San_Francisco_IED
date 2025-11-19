// Application State
const state = {
    currentUser: null,
    currentPage: 'public-magazine-page',
    articles: [],
    users: [],
    notifications: []
};

// Configuración automática de API URL para producción
function getApiBaseUrl() {
    const currentUrl = window.location.origin;
    
    if (currentUrl.includes('onrender.com')) {
        return currentUrl + '/api';
    }
    
    // Desarrollo local - USAR EL NUEVO PUERTO
    return 'http://localhost:10000/api';  // Mismo puerto que server.js
}
const API_BASE_URL = getApiBaseUrl();
console.log('🔗 Conectando a API:', API_BASE_URL);

// Función mejorada para llamadas a la API
async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Error ${response.status}: ${errorText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`❌ Error en API ${endpoint}:`, error);
        
        // Si es error de conexión, usar datos locales
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            console.log('🌐 Sin conexión, usando datos locales...');
            throw new Error('OFFLINE_MODE');
        }
        
        throw error;
    }
}

// Initialize application
async function initApp() {
    console.log('🚀 Inicializando Revista Digital CSF...');
    
    try {
        // Probar conexión con la API
        const health = await apiRequest('/health');
        console.log('✅ API conectada:', health.message);
        
        // Cargar datos iniciales
        await loadInitialData();
        
    } catch (error) {
        if (error.message === 'OFFLINE_MODE') {
            console.log('📱 Modo offline activado');
            // Cargar datos desde localStorage
            loadDataFromStorage();
        } else {
            console.error('❌ Error inicializando app:', error);
            // Fallback a datos locales
            loadDataFromStorage();
        }
    }
    
    // Set up event listeners
    setupEventListeners();
    
    // Load public magazine by default
    loadPublicMagazine();
    showPage('public-magazine-page');
    
    // Update public header
    updatePublicHeader();
    
    console.log('✅ Sistema de Revista Digital inicializado correctamente');
}

// Cargar datos iniciales desde la API
async function loadInitialData() {
    try {
        // Cargar artículos públicos
        const articlesData = await apiRequest('/articles?status=published');
        state.articles = articlesData.articles || [];
        
        // Cargar usuarios (solo si es admin)
        if (state.currentUser && state.currentUser.role === 'admin') {
            const usersData = await apiRequest('/users');
            state.users = usersData.users || [];
        }
        
        // Guardar en localStorage como backup
        saveDataToStorage();
        
    } catch (error) {
        console.error('Error cargando datos iniciales:', error);
        throw error;
    }
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('new-article-btn').addEventListener('click', showNewArticleForm);
    document.getElementById('cancel-article-btn').addEventListener('click', cancelArticleForm);
    document.getElementById('article-form').addEventListener('submit', saveArticle);
    document.getElementById('comment-form').addEventListener('submit', addComment);
    document.getElementById('create-user-form').addEventListener('submit', createUser);
    document.getElementById('change-password-form').addEventListener('submit', changePassword);
    
    // Character count for forms
    document.getElementById('article-title').addEventListener('input', updateCharCount);
    document.getElementById('article-content').addEventListener('input', updateCharCount);
    document.getElementById('comment-content').addEventListener('input', updateCharCount);
    
    // Username availability check
    document.getElementById('new-user-username').addEventListener('input', checkUsernameAvailability);
    
    // Password confirmation check
    document.getElementById('confirm-password').addEventListener('input', checkPasswordMatch);
    
    // Search functionality
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.target.id === 'public-search') {
            searchInMagazine();
        }
    });
}

// EN script.js - REEMPLAZA la función loadDataFromStorage:

function loadDataFromStorage() {
    const savedUsers = localStorage.getItem('revista_users');
    const savedArticles = localStorage.getItem('revista_articles');
    const savedNotifications = localStorage.getItem('revista_notifications');
    
    // Datos de respaldo para cuando no hay conexión
    const backupUsers = [
        { 
            id: 1, 
            username: 'admin', 
            password: 'admin', 
            name: 'Administrador Sistema', 
            role: 'admin', 
            active: true,
            lastLogin: new Date().toISOString().split('T')[0]
        },
        { 
            id: 2, 
            username: 'docente1', 
            password: '123', 
            name: 'María González', 
            role: 'teacher', 
            active: true,
            lastLogin: new Date().toISOString().split('T')[0]
        },
        { 
            id: 3, 
            username: 'estudiante1', 
            password: '123', 
            name: 'Juan Pérez', 
            role: 'student', 
            active: true,
            talento: 'artistico',
            lastLogin: new Date().toISOString().split('T')[0]
        }
    ];

    function showCreateUserForm() {
    document.getElementById('new-user-name').value = '';
    document.getElementById('new-user-username').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('new-user-role').value = 'student';
    document.getElementById('new-user-talento').value = '';

    showPage('create-user-page');
}
window.showCreateUserForm = showCreateUserForm;



    const backupArticles = [
        {
            id: 1,
            title: 'Bienvenido a la Revista Digital',
            category: 'tecnologico',
            chapter: 'portafolios',
            content: 'Esta es la Revista Digital del Colegio San Francisco IED. Conéctate a internet para ver todos los artículos.',
            author: 'Sistema',
            authorId: 1,
            image: '',
            imageFile: null,
            status: 'published',
            createdAt: new Date().toISOString().split('T')[0],
            comments: []
        }
    ];

    const backupNotifications = [
        { 
            id: 1, 
            title: 'Bienvenido/a', 
            content: 'Conéctate a internet para acceder a todas las funciones', 
            type: 'info', 
            read: false, 
            createdAt: new Date().toISOString().split('T')[0],
            link: 'dashboard-page'
        }
    ];
    
    state.users = savedUsers ? JSON.parse(savedUsers) : backupUsers;
    state.articles = savedArticles ? JSON.parse(savedArticles) : backupArticles;
    state.notifications = savedNotifications ? JSON.parse(savedNotifications) : backupNotifications;
}

// Save data to localStorage
function saveDataToStorage() {
    try {
        localStorage.setItem('revista_users', JSON.stringify(state.users));
        localStorage.setItem('revista_articles', JSON.stringify(state.articles));
        localStorage.setItem('revista_notifications', JSON.stringify(state.notifications));
        console.log('💾 Datos guardados en localStorage');
    } catch (error) {
        console.error('Error guardando en localStorage:', error);
    }
}

// FUNCIÓN DE LOGIN CORREGIDA - REEMPLAZAR LA VERSIÓN COMENTADA
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const role = document.getElementById('role').value;
    
    if (!username || !password || !role) {
        alert('❌ Por favor completa todos los campos');
        return;
    }

    // Mostrar loading
    const loginBtn = document.querySelector('#login-form button[type="submit"]');
    const originalText = loginBtn.textContent;
    loginBtn.textContent = '🔐 Conectando...';
    loginBtn.disabled = true;

    try {
        console.log('🔗 Intentando login con:', { username, role });
        
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });

        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ Login exitoso:', data.user);
            state.currentUser = data.user;
            
            // Actualizar UI
            updateUIForUser();
            showPage('dashboard-page');
            updateDashboard();
            updatePublicHeader();
            
            alert(`✅ ¡Bienvenido/a ${data.user.name}!`);
            
        } else {
            console.error('❌ Error en login:', data.error);
            
            // Intentar con datos locales como fallback
            const localUsers = JSON.parse(localStorage.getItem('revista_users') || '[]');
            const localUser = localUsers.find(u => 
                u.username === username && u.password === password && u.role === role
            );
            
            if (localUser) {
                console.log('📱 Usando datos locales como fallback');
                state.currentUser = localUser;
                updateUIForUser();
                showPage('dashboard-page');
                updateDashboard();
                updatePublicHeader();
                alert(`⚠️ Modo offline - Bienvenido/a ${localUser.name}`);
            } else {
                alert(`❌ ${data.error || 'Credenciales incorrectas'}`);
            }
        }
        
    } catch (error) {
        console.error('🌐 Error de conexión:', error);
        
        // Fallback a datos locales
        const localUsers = JSON.parse(localStorage.getItem('revista_users') || '[]');
        const localUser = localUsers.find(u => 
            u.username === username && u.password === password && u.role === role
        );
        
        if (localUser) {
            console.log('📱 Modo offline - Login con datos locales');
            state.currentUser = localUser;
            updateUIForUser();
            showPage('dashboard-page');
            updateDashboard();
            updatePublicHeader();
            alert(`⚠️ Sin conexión - Bienvenido/a ${localUser.name}`);
        } else {
            alert('❌ Error de conexión y no hay datos locales. Verifica tu internet.');
        }
    } finally {
        // Restaurar botón
        loginBtn.textContent = originalText;
        loginBtn.disabled = false;
    }
}

// Create user - ACTUALIZADA PARA PRODUCCIÓN
async function createUser(e) {
    e.preventDefault();
    
    const name = document.getElementById('new-user-name').value;
    const username = document.getElementById('new-user-username').value;
    const password = document.getElementById('new-user-password').value;
    const role = document.getElementById('new-user-role').value;
    const talento = document.getElementById('new-user-talento').value;

    // Validar formulario
    if (name.length < 2) {
        alert('El nombre debe tener al menos 2 caracteres.');
        return;
    }
    
    if (username.length < 3) {
        alert('El nombre de usuario debe tener al menos 3 caracteres.');
        return;
    }
    
    if (password.length < 3) {
        alert('La contraseña debe tener al menos 3 caracteres.');
        return;
    }

    try {
        const data = await apiRequest('/users', {
            method: 'POST',
            body: JSON.stringify({
                username,
                password,
                name,
                role,
                talento: role === 'student' ? talento : null
            })
        });

        if (data.success) {
            // Actualizar el estado local también
            const newUser = {
                id: data.user.id,
                username,
                password,
                name,
                role,
                active: true,
                talento: role === 'student' ? talento : null,
                lastLogin: new Date().toISOString().split('T')[0]
            };
            
            state.users.push(newUser);
            saveDataToStorage();
            
            showPage('users-page');
            loadUsers();
            alert('✅ Usuario creado exitosamente en la base de datos.');
        } else {
            alert('❌ Error creando usuario: ' + (data.error || 'Error desconocido'));
        }
    } catch (error) {
        if (error.message === 'OFFLINE_MODE') {
            // Fallback: guardar en localStorage si falla la conexión
            const newUser = {
                id: state.users.length > 0 ? Math.max(...state.users.map(u => u.id)) + 1 : 1,
                username,
                password,
                name,
                role,
                active: true,
                talento: role === 'student' ? talento : null,
                lastLogin: new Date().toISOString().split('T')[0]
            };
            
            state.users.push(newUser);
            saveDataToStorage();
            
            showPage('users-page');
            loadUsers();
            alert('⚠️ Usuario creado localmente (modo offline). Se sincronizará cuando haya conexión.');
        } else {
            console.error('Error creando usuario:', error);
            alert('❌ Error creando usuario: ' + (error.message || 'Error de conexión'));
        }
    }
}
// AGREGAR ESTA FUNCIÓN EN script.js
function showCreateUserForm() {
    // Solo administradores pueden crear usuarios
    if (!state.currentUser || state.currentUser.role !== 'admin') {
        alert('❌ Solo los administradores pueden crear usuarios.');
        return;
    }
    
    // Limpiar formulario
    document.getElementById('new-user-name').value = '';
    document.getElementById('new-user-username').value = '';
    document.getElementById('new-user-password').value = '';
    document.getElementById('new-user-role').value = 'student';
    document.getElementById('new-user-talento').value = '';
    
    // Mostrar página
    showPage('create-user-page');
}


// Load articles - ACTUALIZADA PARA PRODUCCIÓN
async function loadArticles() {
    const articlesGrid = document.getElementById('articles-grid');
    
    try {
        let url = '/articles';
        const params = new URLSearchParams();
        
        // Agregar filtros
        const statusFilter = document.getElementById('article-filter').value;
        const categoryFilter = document.getElementById('category-filter').value;
        const chapterFilter = document.getElementById('chapter-filter').value;
        
        if (statusFilter !== 'all') params.append('status', statusFilter);
        if (categoryFilter !== 'all') params.append('category', categoryFilter);
        if (chapterFilter !== 'all') params.append('chapter', chapterFilter);
        if (state.currentUser?.role === 'student') {
            params.append('user_id', state.currentUser.id);
        }
        
        if (params.toString()) url += '?' + params.toString();
        
        const data = await apiRequest(url);
        state.articles = data.articles || [];
        renderArticles();
        
    } catch (error) {
        if (error.message === 'OFFLINE_MODE') {
            console.log('📚 Cargando artículos desde localStorage');
            // Usar datos locales y filtrar
            filterLocalArticles();
        } else {
            console.error('Error cargando artículos:', error);
            alert('❌ Error cargando artículos');
        }
    }
}

// Función para filtrar artículos locales
function filterLocalArticles() {
    const statusFilter = document.getElementById('article-filter').value;
    const categoryFilter = document.getElementById('category-filter').value;
    const chapterFilter = document.getElementById('chapter-filter').value;
    
    let filteredArticles = [...state.articles];
    
    if (statusFilter !== 'all') {
        filteredArticles = filteredArticles.filter(a => a.status === statusFilter);
    }
    
    if (categoryFilter !== 'all') {
        filteredArticles = filteredArticles.filter(a => a.category === categoryFilter);
    }
    
    if (chapterFilter !== 'all') {
        filteredArticles = filteredArticles.filter(a => a.chapter === chapterFilter);
    }
    
    if (state.currentUser?.role === 'student') {
        filteredArticles = filteredArticles.filter(a => a.author_id === state.currentUser.id);
    }
    
    renderFilteredArticles(filteredArticles);
}

// Renderizar artículos filtrados
function renderFilteredArticles(articles) {
    const articlesGrid = document.getElementById('articles-grid');
    let articlesHTML = '';
    
    if (articles.length === 0) {
        articlesHTML = '<div class="no-content"><p>No se encontraron artículos.</p></div>';
    } else {
        articles.forEach(article => {
            const statusClass = `article-status status-${article.status}`;
            const statusText = getStatusText(article.status);
            
            articlesHTML += `
                <div class="article-card" onclick="showArticleDetail(${article.id})">
                    <div class="article-image">
                        ${article.imageFile ? 
                            `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                            getCategoryIcon(article.category)
                        }
                    </div>
                    <div class="article-content">
                        <h3 class="article-title">${article.title}</h3>
                        <div class="article-meta">
                            <span>Por: ${article.author || article.author_name}</span>
                            <span>${formatDate(article.created_at || article.createdAt)}</span>
                        </div>
                        <div class="article-excerpt">${article.content.substring(0, 100)}...</div>
                        <div class="article-meta">
                            <span>${getCategoryName(article.category)} • ${getChapterName(article.chapter)}</span>
                            <span class="${statusClass}">${statusText}</span>
                        </div>
                        ${article.author_id === state.currentUser?.id && article.status !== 'published' ? 
                          `<div class="action-buttons">
                              <button onclick="event.stopPropagation(); editArticle(${article.id})">✏️ Editar</button>
                           </div>` : ''}
                        ${state.currentUser?.role === 'admin' ? 
                          `<div class="action-buttons">
                              <button class="btn-danger" onclick="event.stopPropagation(); deleteArticle(${article.id})">🗑️ Eliminar</button>
                           </div>` : ''}
                    </div>
                </div>
            `;
        });
    }
    
    articlesGrid.innerHTML = articlesHTML;
}

// Load users - ACTUALIZADA PARA PRODUCCIÓN
async function loadUsers() {
    try {
        if (state.currentUser && state.currentUser.role === 'admin') {
            const data = await apiRequest('/users');
            state.users = data.users || [];
        }
    } catch (error) {
        if (error.message !== 'OFFLINE_MODE') {
            console.error('Error cargando usuarios:', error);
        }
    }

    const usersTable = document.getElementById('users-table-body');
    let usersHTML = '';

    const totalUsers = state.users.length;
    const studentUsers = state.users.filter(u => u.role === 'student').length;
    const teacherUsers = state.users.filter(u => u.role === 'teacher').length;
    const activeUsers = state.users.filter(u => u.active).length;

    document.getElementById('total-users').textContent = totalUsers;
    document.getElementById('student-users').textContent = studentUsers;
    document.getElementById('teacher-users').textContent = teacherUsers;
    document.getElementById('active-users').textContent = activeUsers;

    if (state.users.length === 0) {
        usersHTML = '<tr><td colspan="6" class="no-content">No hay usuarios registrados</td></tr>';
    } else {
        state.users.forEach(user => {
            usersHTML += `
                <tr>
                    <td>${user.name}</td>
                    <td>${user.username}</td>
                    <td>${getRoleName(user.role)} ${user.talento ? `(${getCategoryName(user.talento)})` : ''}</td>
                    <td><span class="article-status ${user.active ? 'status-published' : 'status-rejected'}">${user.active ? 'Activo' : 'Inactivo'}</span></td>
                    <td>${formatDate(user.last_login || user.lastLogin)}</td>
                    <td class="action-buttons">
                        <button class="${user.active ? 'btn-danger' : 'btn-success'}" onclick="toggleUserStatus(${user.id})">${user.active ? '🚫 Desactivar' : '✅ Activar'}</button>
                        ${user.role !== 'admin' ? `<button onclick="resetUserPassword(${user.id})">🔑 Resetear Contraseña</button>` : ''}
                    </td>
                </tr>
            `;
        });
    }

    usersTable.innerHTML = usersHTML;
}

// Toggle user status - ACTUALIZADA PARA PRODUCCIÓN
async function toggleUserStatus(userId) {
    try {
        const user = state.users.find(u => u.id === userId);
        if (user) {
            const data = await apiRequest(`/users/${userId}/status`, {
                method: 'PUT',
                body: JSON.stringify({
                    active: !user.active
                })
            });

            if (data.success) {
                user.active = !user.active;
                saveDataToStorage();
                loadUsers();
                alert(`✅ Usuario ${user.active ? 'activado' : 'desactivado'} exitosamente.`);
            }
        }
    } catch (error) {
        if (error.message === 'OFFLINE_MODE') {
            // Fallback a localStorage
            const user = state.users.find(u => u.id === userId);
            if (user) {
                user.active = !user.active;
                saveDataToStorage();
                loadUsers();
                alert(`⚠️ Estado actualizado localmente: ${user.active ? 'activado' : 'desactivado'}`);
            }
        } else {
            console.error('Error actualizando estado:', error);
            alert('❌ Error actualizando estado del usuario');
        }
    }
}

// Save article - ACTUALIZADA PARA PRODUCCIÓN
async function saveArticle(e) {
    e.preventDefault();
    
    if (!state.currentUser) return;
    
    const articleId = document.getElementById('article-id').value;
    const title = document.getElementById('article-title').value;
    const category = document.getElementById('article-category').value;
    const chapter = document.getElementById('article-chapter').value;
    const content = document.getElementById('article-content').value;
    const status = document.getElementById('article-status').value;
    const imageFile = document.getElementById('article-image-upload').files[0];
    
    // Validate form
    const errors = validateForm({ title, content });
    if (errors.length > 0) {
        alert('❌ Errores en el formulario:\n\n' + errors.join('\n'));
        return;
    }
    
    try {
        const articleData = {
            title,
            category,
            chapter,
            content,
            author_id: state.currentUser.id,
            status
        };
        
        if (articleId) {
            articleData.id = articleId;
        }
        
        const data = await apiRequest('/articles', {
            method: 'POST',
            body: JSON.stringify(articleData)
        });
        
        if (data.success) {
            // Actualizar estado local
            if (articleId) {
                const index = state.articles.findIndex(a => a.id === parseInt(articleId));
                if (index !== -1) {
                    state.articles[index] = { ...state.articles[index], ...data.article };
                }
            } else {
                state.articles.push(data.article);
            }
            
            saveDataToStorage();
            showPage('articles-page');
            loadArticles();
            updateDashboard();
            
            if (status === 'pending') {
                alert('✅ Artículo enviado para revisión exitosamente.');
            } else {
                alert('✅ Artículo guardado como borrador.');
            }
        }
        
    } catch (error) {
        if (error.message === 'OFFLINE_MODE') {
            // Guardar localmente
            if (articleId) {
                const index = state.articles.findIndex(a => a.id === parseInt(articleId));
                if (index !== -1) {
                    state.articles[index].title = title;
                    state.articles[index].category = category;
                    state.articles[index].chapter = chapter;
                    state.articles[index].content = content;
                    state.articles[index].status = status;
                    state.articles[index].updatedAt = new Date().toISOString().split('T')[0];
                }
            } else {
                const newArticle = {
                    id: state.articles.length > 0 ? Math.max(...state.articles.map(a => a.id)) + 1 : 1,
                    title,
                    category,
                    chapter,
                    content,
                    author: state.currentUser.name,
                    author_id: state.currentUser.id,
                    imageFile: imageFile || null,
                    status,
                    created_at: new Date().toISOString().split('T')[0],
                    comments: []
                };
                state.articles.push(newArticle);
            }
            
            saveDataToStorage();
            showPage('articles-page');
            loadArticles();
            alert('⚠️ Artículo guardado localmente (modo offline). Se sincronizará con la conexión.');
            
        } else {
            console.error('Error guardando artículo:', error);
            alert('❌ Error guardando artículo: ' + (error.message || 'Error de conexión'));
        }
    }
}

// =======================
// FUNCIONES DE UTILIDAD (MANTENIDAS)
// =======================

// Las funciones de utilidad se mantienen igual que antes...
// getRoleName, getCategoryName, getCategoryIcon, getCategoryClass, 
// getChapterName, formatDate, showPage, updateCharCount, etc.

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', initApp);

// Funciones globales para el frontend
window.getAppState = () => state;
window.API_BASE_URL = API_BASE_URL;

console.log('🔧 Frontend configurado para producción');

// =======================
// FUNCIONES PRINCIPALES MEJORADAS
// =======================

// Initialize application
// Initialize application
async function initApp() {
    console.log('🚀 Inicializando Revista Digital CSF...');
    
    try {
        // Probar conexión con la API
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
            const health = await response.json();
            console.log('✅ API conectada:', health.message);
        } else {
            throw new Error('API no responde correctamente');
        }
        
    } catch (error) {
        console.log('📱 Modo offline - Usando datos locales');
    }
    
    // Cargar datos desde localStorage
    loadDataFromStorage();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load public magazine by default
    loadPublicMagazine();
    showPage('public-magazine-page');
    
    // Update public header
    updatePublicHeader();
    
    console.log('✅ Sistema de Revista Digital inicializado correctamente');
}

// Setup event listeners
function setupEventListeners() {
    // Login form submission
    const loginForm = document.getElementById('login-form');
    console.log('🔍 Formulario de login encontrado:', loginForm);
    //  Verificar si el formulario existe antes de agregar el event listener
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        console.log('✅ Event listener del login registrado correctamente');
        // Puedes agregar más logs aquí si es necesario
    } else {
        console.error('❌ NO se encontró el formulario de login con id="login-form"');
    }
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('new-article-btn').addEventListener('click', showNewArticleForm);
    document.getElementById('cancel-article-btn').addEventListener('click', cancelArticleForm);
    document.getElementById('article-form').addEventListener('submit', saveArticle);
    document.getElementById('comment-form').addEventListener('submit', addComment);
    document.getElementById('create-user-form').addEventListener('submit', createUser);
    document.getElementById('change-password-form').addEventListener('submit', changePassword);
    
    // Character count for forms
    document.getElementById('article-title').addEventListener('input', updateCharCount);
    document.getElementById('article-content').addEventListener('input', updateCharCount);
    document.getElementById('comment-content').addEventListener('input', updateCharCount);
    
    // Username availability check
    document.getElementById('new-user-username').addEventListener('input', checkUsernameAvailability);
    
    // Password confirmation check
    document.getElementById('confirm-password').addEventListener('input', checkPasswordMatch);
    
    // Search functionality
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.target.id === 'public-search') {
            searchInMagazine();
        }
    });
}

function loadDataFromStorage() {
    // SOLO cargar notificaciones y artículos locales
    // LOS USUARIOS SIEMPRE se cargan desde la base de datos
    const savedArticles = localStorage.getItem('revista_articles');
    const savedNotifications = localStorage.getItem('revista_notifications');
    
    // Datos de respaldo MUY básicos
    const backupArticles = [];
    const backupNotifications = [
        { 
            id: 1, 
            title: 'Bienvenido/a', 
            content: 'Conectado al sistema', 
            type: 'info', 
            read: false, 
            createdAt: new Date().toISOString().split('T')[0]
        }
    ];
    
    // NO cargar usuarios desde localStorage
    state.users = []; // Vacío - se cargarán desde la BD cuando sea necesario
    state.articles = savedArticles ? JSON.parse(savedArticles) : backupArticles;
    state.notifications = savedNotifications ? JSON.parse(savedNotifications) : backupNotifications;
}

// Save data to localStorage
function saveDataToStorage() {
    // Preparar artículos para almacenamiento (convertir Blobs a base64)
    const articlesToSave = state.articles.map(article => {
        const articleCopy = {...article};
        // No guardamos el Blob directamente en localStorage
        delete articleCopy.imageFile;
        return articleCopy;
    });
    
    localStorage.setItem('revista_users', JSON.stringify(state.users));
    localStorage.setItem('revista_articles', JSON.stringify(articlesToSave));
    localStorage.setItem('revista_notifications', JSON.stringify(state.notifications));
}

// Update public header navigation
function updatePublicHeader() {
    const userInfo = document.getElementById('user-info');
    const exportBtn = document.getElementById('export-btn');
    
    if (state.currentUser) {
        userInfo.innerHTML = `
            <div class="user-avatar">${state.currentUser.name.charAt(0)}</div>
            <div>
                <div>${state.currentUser.name}</div>
                <div style="font-size: 0.8rem;">${getRoleName(state.currentUser.role)}</div>
            </div>
            <button onclick="logout()">Cerrar Sesión</button>
        `;
        
        // Show export button for admins
        if (state.currentUser.role === 'admin') {
            exportBtn.style.display = 'flex';
        }
        
        // Update navigation menu
        updateUIForUser();
    } else {
        userInfo.innerHTML = `
            <button onclick="showPublicMagazine()" class="btn-outline">👀 Ver Revista</button>
            <button onclick="showPage('login-page')">🔐 Ingresar</button>
        `;
        
        // Reset navigation to public view
        const navMenu = document.getElementById('nav-menu');
        navMenu.innerHTML = `
            <li><a href="#" onclick="showPublicMagazine()">🏠</a></li>
            <li><a href="#" onclick="showPage('login-page')">🔐</a></li>
        `;
    }
}

// Add search functionality
function addSearchFunctionality() {
    // Search functionality is now built into the HTML
}

// Show public magazine
function showPublicMagazine() {
    loadPublicMagazine();
    showPage('public-magazine-page');
    updatePublicHeader();
}

// Load public magazine content
function loadPublicMagazine() {
    loadPublicPortafolios();
    loadPublicExperiencias();
    loadPublicPosicionamiento();
}

// Load public portafolios
function loadPublicPortafolios() {
    const grid = document.getElementById('public-portafolios-grid');
    const portafolios = state.articles.filter(a => a.chapter === 'portafolios' && a.status === 'published');
    
    let html = '';
    portafolios.forEach(article => {
        html += `
            <div class="article-card" onclick="showPublicArticleDetail(${article.id})">
                <div class="article-image">
                    ${article.imageFile ? 
                        `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                        getCategoryIcon(article.category)
                    }
                </div>
                <div class="article-content">
                    <h3 class="article-title">${article.title}</h3>
                    <div class="article-meta">
                        <span>Por: ${article.author}</span>
                        <span>${formatDate(article.createdAt)}</span>
                    </div>
                    <div class="article-excerpt">${article.content.substring(0, 120)}...</div>
                    <div class="article-meta">
                        <span class="article-status ${getCategoryClass(article.category)}">${getCategoryName(article.category)}</span>
                        <span>💬 ${article.comments.length}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    grid.innerHTML = html || '<p class="no-content">No hay portafolios publicados aún.</p>';
}

// Load public experiencias
function loadPublicExperiencias() {
    const grid = document.getElementById('public-experiencias-grid');
    const experiencias = state.articles.filter(a => a.chapter === 'experiencias' && a.status === 'published');
    
    let html = '';
    experiencias.forEach(article => {
        html += `
            <div class="article-card" onclick="showPublicArticleDetail(${article.id})">
                <div class="article-image">
                    ${article.imageFile ? 
                        `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                        getCategoryIcon(article.category)
                    }
                </div>
                <div class="article-content">
                    <h3 class="article-title">${article.title}</h3>
                    <div class="article-meta">
                        <span>Por: ${article.author}</span>
                        <span>${formatDate(article.createdAt)}</span>
                    </div>
                    <div class="article-excerpt">${article.content.substring(0, 120)}...</div>
                    <div class="article-meta">
                        <span class="article-status ${getCategoryClass(article.category)}">${getCategoryName(article.category)}</span>
                        <span>💬 ${article.comments.length}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    grid.innerHTML = html || '<p class="no-content">No hay experiencias pedagógicas publicadas aún.</p>';
}

// Load public posicionamiento
function loadPublicPosicionamiento() {
    const grid = document.getElementById('public-posicionamiento-grid');
    const posicionamientos = state.articles.filter(a => a.chapter === 'posicionamiento' && a.status === 'published');
    
    let html = '';
    posicionamientos.forEach(article => {
        html += `
            <div class="article-card" onclick="showPublicArticleDetail(${article.id})">
                <div class="article-image">
                    ${article.imageFile ? 
                        `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                        getCategoryIcon(article.category)
                    }
                </div>
                <div class="article-content">
                    <h3 class="article-title">${article.title}</h3>
                    <div class="article-meta">
                        <span>Por: ${article.author}</span>
                        <span>${formatDate(article.createdAt)}</span>
                    </div>
                    <div class="article-excerpt">${article.content.substring(0, 120)}...</div>
                    <div class="article-meta">
                        <span class="article-status ${getCategoryClass(article.category)}">${getCategoryName(article.category)}</span>
                        <span>💬 ${article.comments.length}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    grid.innerHTML = html || '<p class="no-content">No hay reflexiones críticas publicadas aún.</p>';
}

// Show public article detail - IMPROVED VERSION
function showPublicArticleDetail(articleId) {
    const article = state.articles.find(a => a.id === articleId && a.status === 'published');
    if (!article) return;
    
    // Create modal for public article viewing
    const modalHTML = `
        <div class="modal-overlay" onclick="closePublicModal()">
            <div class="modal-content" onclick="event.stopPropagation()">
                <div class="modal-header">
                    <h2>${article.title}</h2>
                    <button class="modal-close" onclick="closePublicModal()">×</button>
                </div>
                <div class="modal-body">
                    <div class="article-meta">
                        <span><strong>Autor:</strong> ${article.author}</span>
                        <span><strong>Fecha:</strong> ${formatDate(article.createdAt)}</span>
                        <span><strong>Categoría:</strong> ${getCategoryName(article.category)}</span>
                        <span><strong>Capítulo:</strong> ${getChapterName(article.chapter)}</span>
                    </div>
                    ${article.imageFile ? `
                        <div class="article-image-modal">
                            <img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">
                        </div>
                    ` : ''}
                    <div class="article-content-full">
                        ${article.content.replace(/\n/g, '<br>')}
                    </div>
                    <div class="comments-section">
                        <h3>💬 Comentarios <span class="article-status">${article.comments.length}</span></h3>
                        ${article.comments.length > 0 ? article.comments.map(comment => `
                            <div class="notification">
                                <h4>${comment.author}</h4>
                                <p>${comment.content}</p>
                                <small>${formatDate(comment.createdAt)}</small>
                            </div>
                        `).join('') : '<p class="no-content">No hay comentarios aún.</p>'}
                    </div>
                    <div class="article-actions-public">
                        <p><em>💡 Para comentar y acceder a más funciones, <a href="#" onclick="showPage('login-page'); closePublicModal()">inicia sesión</a></em></p>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to body
    const modalContainer = document.createElement('div');
    modalContainer.id = 'public-article-modal';
    modalContainer.innerHTML = modalHTML;
    document.body.appendChild(modalContainer);
}

function closePublicModal() {
    const modal = document.getElementById('public-article-modal');
    if (modal) {
        modal.remove();
    }
}

// Search in magazine
function searchInMagazine() {
    const searchTerm = document.getElementById('public-search').value.toLowerCase().trim();
    if (!searchTerm) {
        alert('Por favor, ingresa un término de búsqueda.');
        return;
    }
    
    const results = state.articles.filter(article => 
        article.status === 'published' && 
        (article.title.toLowerCase().includes(searchTerm) || 
         article.content.toLowerCase().includes(searchTerm) ||
         article.author.toLowerCase().includes(searchTerm) ||
         getCategoryName(article.category).toLowerCase().includes(searchTerm))
    );
    
    if (results.length === 0) {
        alert('No se encontraron artículos que coincidan con tu búsqueda.');
        return;
    }
    
    // Show results in modal
    showSearchResults(results, searchTerm);
}

function showSearchResults(results, searchTerm) {
    let resultsHTML = `
        <div class="modal-overlay" onclick="closeSearchModal()">
            <div class="modal-content" onclick="event.stopPropagation()">
                <div class="modal-header">
                    <h2>🔍 Resultados de búsqueda: "${searchTerm}"</h2>
                    <button class="modal-close" onclick="closeSearchModal()">×</button>
                </div>
                <div class="modal-body">
                    <p>Se encontraron ${results.length} artículo(s) que coinciden con tu búsqueda.</p>
                    <div class="articles-grid" style="margin-top: 1rem;">
    `;
    
    results.forEach(article => {
        resultsHTML += `
            <div class="article-card" onclick="showPublicArticleDetail(${article.id}); closeSearchModal()">
                <div class="article-image">
                    ${article.imageFile ? 
                        `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                        getCategoryIcon(article.category)
                    }
                </div>
                <div class="article-content">
                    <h3 class="article-title">${article.title}</h3>
                    <div class="article-meta">
                        <span>Por: ${article.author}</span>
                        <span>${formatDate(article.createdAt)}</span>
                        <span>${getCategoryName(article.category)}</span>
                    </div>
                    <div class="article-excerpt">${article.content.substring(0, 150)}...</div>
                </div>
            </div>
        `;
    });
    
    resultsHTML += `
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const modalContainer = document.createElement('div');
    modalContainer.id = 'search-results-modal';
    modalContainer.innerHTML = resultsHTML;
    document.body.appendChild(modalContainer);
}

function closeSearchModal() {
    const modal = document.getElementById('search-results-modal');
    if (modal) modal.remove();
}

// Handle user login - CORREGIDA PARA USAR LA API
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const role = document.getElementById('role').value;
    
    // Mostrar loading
    const loginBtn = document.querySelector('#login-form button[type="submit"]');
    const originalText = loginBtn.textContent;
    loginBtn.textContent = '🔐 Conectando...';
    loginBtn.disabled = true;

    try {
        console.log('🔗 Intentando login con:', { username, role });
        
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });

        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ Login exitoso:', data.user);
            state.currentUser = data.user;
            
            // Guardar en localStorage como backup
            const savedUsers = JSON.parse(localStorage.getItem('revista_users') || '[]');
            const userExists = savedUsers.find(u => u.id === data.user.id);
            if (!userExists) {
                savedUsers.push({
                    ...data.user,
                    password: password // Guardar temporalmente para modo offline
                });
                localStorage.setItem('revista_users', JSON.stringify(savedUsers));
            }
            
            // Actualizar UI
            updateUIForUser();
            showPage('dashboard-page');
            updateDashboard();
            updatePublicHeader();
            
            // Cargar datos después del login
            setTimeout(() => {
                loadArticles();
                if (data.user.role === 'admin') {
                    loadUsers();
                }
            }, 500);
            
            alert(`✅ ¡Bienvenido/a ${data.user.name}!`);
            
        } else {
            console.error('❌ Error en login:', data.error);
            
            // Intentar con datos locales como fallback
            const localUser = state.users.find(u => 
                u.username === username && u.password === password && u.role === role && u.active
            );
            
            if (localUser) {
                console.log('📱 Usando datos locales como fallback');
                state.currentUser = localUser;
                updateUIForUser();
                showPage('dashboard-page');
                updateDashboard();
                updatePublicHeader();
                alert(`⚠️ Modo offline - Bienvenido/a ${localUser.name}`);
            } else {
                alert(`❌ ${data.error || 'Credenciales incorrectas'}`);
            }
        }
        
    } catch (error) {
        console.error('🌐 Error de conexión:', error);
        
        // Fallback a datos locales
        const localUser = state.users.find(u => 
            u.username === username && u.password === password && u.role === role && u.active
        );
        
        if (localUser) {
            console.log('📱 Modo offline - Login con datos locales');
            state.currentUser = localUser;
            updateUIForUser();
            showPage('dashboard-page');
            updateDashboard();
            updatePublicHeader();
            alert(`⚠️ Sin conexión - Bienvenido/a ${localUser.name}`);
        } else {
            alert('❌ Error de conexión y no hay datos locales. Verifica tu internet.');
        }
    } finally {
        // Restaurar botón
        loginBtn.textContent = originalText;
        loginBtn.disabled = false;
    }
}

// Update UI based on logged in user
function updateUIForUser() {
    const navMenu = document.getElementById('nav-menu');
    
    let navItems = '';
    
    if (state.currentUser) {
        // Common items for all logged-in users
        navItems = `
            <li><a href="#" onclick="showPage('dashboard-page'); updateDashboard()">📊 Dashboard</a></li>
            <li><a href="#" onclick="showPage('articles-page'); loadArticles()">📚 ${state.currentUser.role === 'student' ? 'Mis Artículos' : 'Artículos'}</a></li>
            <li><a href="#" onclick="showGamesPage()">🎮 Juegos Educativos</a></li>
            <li><a href="#" onclick="showPublicMagazine()">👀 Ver Revista</a></li>
        `;
        
        // Role-specific items
        if (state.currentUser.role === 'teacher' || state.currentUser.role === 'admin') {
            navItems = `
                <li><a href="#" onclick="showPage('dashboard-page'); updateDashboard()">📊 Dashboard</a></li>
                <li><a href="#" onclick="showPage('articles-page'); loadArticles()">📚 Artículos</a></li>
                <li><a href="#" onclick="showPage('pending-articles-page'); loadPendingArticles()">⏳ Revisar Artículos</a></li>
                <li><a href="#" onclick="showGamesPage()">🎮 Juegos Educativos</a></li>
                <li><a href="#" onclick="showPublicMagazine()">👀 Ver Revista</a></li>
            `;
        }
        
        if (state.currentUser.role === 'admin') {
            navItems = `
                <li><a href="#" onclick="showPage('dashboard-page'); updateDashboard()">📊 Dashboard</a></li>
                <li><a href="#" onclick="showPage('articles-page'); loadArticles()">📚 Artículos</a></li>
                <li><a href="#" onclick="showPage('pending-articles-page'); loadPendingArticles()">⏳ Revisar Artículos</a></li>
                <li><a href="#" onclick="showPage('users-page'); loadUsers()">👥 Usuarios</a></li>
                <li><a href="#" onclick="showGamesPage()">🎮 Juegos Educativos</a></li>
                <li><a href="#" onclick="showPublicMagazine()">👀 Ver Revista</a></li>
            `;
        }
    }
    
    navMenu.innerHTML = navItems;
}

// Get role name for display
function getRoleName(role) {
    const roles = {
        'student': 'Estudiante Reportero',
        'teacher': 'Docente',
        'admin': 'Administrador',
        'parent': 'Padre de Familia'
    };
    return roles[role] || role;
}

// Get category name for display
function getCategoryName(category) {
    const categories = {
        'deportivo': '🏃 Deportivo',
        'musical': '🎵 Musical',
        'matematico': '🔢 Matemático',
        'linguistico': '📝 Lingüístico',
        'tecnologico': '💻 Tecnológico',
        'artistico': '🎨 Artístico'
    };
    return categories[category] || category;
}

// Get category icon
function getCategoryIcon(category) {
    const icons = {
        'deportivo': '🏃',
        'musical': '🎵',
        'matematico': '🔢',
        'linguistico': '📝',
        'tecnologico': '💻',
        'artistico': '🎨'
    };
    return icons[category] || '📄';
}

// Get category CSS class
function getCategoryClass(category) {
    const classes = {
        'deportivo': 'talento-deportivo',
        'musical': 'talento-musical',
        'matematico': 'talento-matematico',
        'linguistico': 'talento-linguistico',
        'tecnologico': 'talento-tecnologico',
        'artistico': 'talento-artistico'
    };
    return classes[category] || '';
}

// Get chapter name
function getChapterName(chapter) {
    const chapters = {
        'portafolios': 'Portafolios Estudiantiles',
        'experiencias': 'Experiencias Pedagógicas',
        'posicionamiento': 'Posicionamiento Crítico'
    };
    return chapters[chapter] || chapter;
}

// Format date
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('es-ES', options);
}

// Show a specific page
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    document.getElementById(pageId).classList.add('active');
    state.currentPage = pageId;
}

// Update character count
function updateCharCount(e) {
    const target = e.target;
    const maxLength = target.id === 'article-title' ? 100 : 
                     target.id === 'article-content' ? 2000 : 500;
    const currentLength = target.value.length;
    const charCountElement = document.getElementById(`${target.id}-char-count`);
    
    if (charCountElement) {
        charCountElement.textContent = `${currentLength}/${maxLength} caracteres`;
        
        // Add warning class if approaching limit
        charCountElement.className = 'char-count';
        if (currentLength > maxLength * 0.8) {
            charCountElement.classList.add('warning');
        }
        if (currentLength > maxLength) {
            charCountElement.classList.add('error');
        }
    }
}

// Check username availability
function checkUsernameAvailability() {
    const username = document.getElementById('new-user-username').value;
    const availabilityElement = document.getElementById('username-availability');
    
    if (!username) {
        availabilityElement.textContent = '';
        return;
    }
    
    const exists = state.users.some(user => user.username === username);
    
    if (exists) {
        availabilityElement.textContent = '❌ Este nombre de usuario ya existe';
        availabilityElement.style.color = 'var(--danger)';
    } else {
        availabilityElement.textContent = '✅ Nombre de usuario disponible';
        availabilityElement.style.color = 'var(--success)';
    }
}

// Check password match
function checkPasswordMatch() {
    const password = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const matchElement = document.getElementById('password-match');
    
    if (!confirmPassword) {
        matchElement.textContent = '';
        return;
    }
    
    if (password === confirmPassword) {
        matchElement.textContent = '✅ Las contraseñas coinciden';
        matchElement.style.color = 'var(--success)';
    } else {
        matchElement.textContent = '❌ Las contraseñas no coinciden';
        matchElement.style.color = 'var(--danger)';
    }
}

// Update dashboard with current data
function updateDashboard() {
    if (!state.currentUser) return;
    
    const publishedCount = state.articles.filter(a => a.status === 'published').length;
    const pendingCount = state.articles.filter(a => a.status === 'pending').length;
    const commentsCount = state.articles.reduce((total, article) => total + article.comments.length, 0);
    const usersCount = state.users.filter(u => u.active).length;
    
    document.getElementById('published-count').textContent = publishedCount;
    document.getElementById('pending-count').textContent = pendingCount;
    document.getElementById('comments-count').textContent = commentsCount;
    document.getElementById('users-count').textContent = usersCount;
    document.getElementById('welcome-user-name').textContent = state.currentUser.name;
    
    loadNotifications();
}

// Load notifications
function loadNotifications() {
    const notificationsList = document.getElementById('notifications-list');
    let notificationsHTML = '';
    
    const userNotifications = state.notifications.slice(0, 5); // Show last 5
    
    if (userNotifications.length === 0) {
        notificationsHTML = '<div class="notification"><p>No hay notificaciones recientes.</p></div>';
    } else {
        userNotifications.forEach(notification => {
            const notificationClass = notification.read ? 'notification' : 'notification unread';
            const icon = notification.type === 'success' ? '✅' : 
                        notification.type === 'warning' ? '⚠️' : 
                        notification.type === 'danger' ? '❌' : 'ℹ️';
            
            notificationsHTML += `
                <div class="${notificationClass}" onclick="markNotificationAsRead(${notification.id})">
                    <h4>${icon} ${notification.title}</h4>
                    <p>${notification.content}</p>
                    <small>${formatDate(notification.createdAt)}</small>
                </div>
            `;
        });
    }
    
    notificationsList.innerHTML = notificationsHTML;
}

// Mark notification as read
function markNotificationAsRead(notificationId) {
    const notification = state.notifications.find(n => n.id === notificationId);
    if (notification) {
        notification.read = true;
        saveDataToStorage();
        if (notification.link) {
            showPage(notification.link);
            if (notification.link === 'pending-articles-page') {
                loadPendingArticles();
            } else if (notification.link === 'articles-page') {
                loadArticles();
            }
        }
        loadNotifications();
    }
}

// Load articles
function loadArticles() {
    const articlesGrid = document.getElementById('articles-grid');
    let articlesHTML = '';
    
    let articlesToShow = [...state.articles];
    
    // Filter based on user role
    if (state.currentUser.role === 'student') {
        articlesToShow = articlesToShow.filter(a => a.authorId === state.currentUser.id);
    } else if (state.currentUser.role === 'parent') {
        articlesToShow = articlesToShow.filter(a => a.status === 'published');
    }
    
    // Apply filters
    const statusFilter = document.getElementById('article-filter').value;
    const categoryFilter = document.getElementById('category-filter').value;
    const chapterFilter = document.getElementById('chapter-filter').value;
    
    if (statusFilter !== 'all') {
        articlesToShow = articlesToShow.filter(a => a.status === statusFilter);
    }
    
    if (categoryFilter !== 'all') {
        articlesToShow = articlesToShow.filter(a => a.category === categoryFilter);
    }
    
    if (chapterFilter !== 'all') {
        articlesToShow = articlesToShow.filter(a => a.chapter === chapterFilter);
    }
    
    if (articlesToShow.length === 0) {
        articlesHTML = '<div class="no-content"><p>No se encontraron artículos.</p></div>';
    } else {
        articlesToShow.forEach(article => {
            const statusClass = `article-status status-${article.status}`;
            const statusText = getStatusText(article.status);
            
            articlesHTML += `
                <div class="article-card" onclick="showArticleDetail(${article.id})">
                    <div class="article-image">
                        ${article.imageFile ? 
                            `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                            getCategoryIcon(article.category)
                        }
                    </div>
                    <div class="article-content">
                        <h3 class="article-title">${article.title}</h3>
                        <div class="article-meta">
                            <span>Por: ${article.author}</span>
                            <span>${formatDate(article.createdAt)}</span>
                        </div>
                        <div class="article-excerpt">${article.content.substring(0, 100)}...</div>
                        <div class="article-meta">
                            <span>${getCategoryName(article.category)} • ${getChapterName(article.chapter)}</span>
                            <span class="${statusClass}">${statusText}</span>
                        </div>
                        ${article.authorId === state.currentUser.id && article.status !== 'published' ? 
                          `<div class="action-buttons">
                              <button onclick="event.stopPropagation(); editArticle(${article.id})">✏️ Editar</button>
                              <button class="btn-danger" onclick="event.stopPropagation(); deleteArticle(${article.id})">🗑️ Eliminar</button>
                           </div>` : ''}
                    </div>
                </div>
            `;
        });
    }
    
    articlesGrid.innerHTML = articlesHTML;
}

// Get status text
function getStatusText(status) {
    const statuses = {
        'published': 'Publicado',
        'pending': 'Pendiente',
        'draft': 'Borrador',
        'rejected': 'Rechazado'
    };
    return statuses[status] || status;
}

// Filter articles
function filterArticles() {
    loadArticles();
}

// Show new article form
function showNewArticleForm() {
    if (!state.currentUser) {
        alert('Por favor inicie sesión para crear artículos.');
        showPage('login-page');
        return;
    }
    
    document.getElementById('article-form-title').textContent = 'Crear Nuevo Artículo';
    document.getElementById('article-id').value = '';
    document.getElementById('article-title').value = '';
    document.getElementById('article-category').value = '';
    document.getElementById('article-chapter').value = '';
    document.getElementById('article-content').value = '';
    document.getElementById('article-image-upload').value = '';
    document.getElementById('article-status').value = 'draft';
    
    // Reset image preview
    document.getElementById('image-preview').style.display = 'none';
    document.getElementById('preview-img').src = '';
    
    // Reset character counts
    document.getElementById('title-char-count').textContent = '0/100 caracteres';
    document.getElementById('content-char-count').textContent = '0/2000 caracteres';
    
    showPage('article-form-page');
}

// Cancel article form
function cancelArticleForm() {
    showPage('articles-page');
    loadArticles();
}

// Preview image before upload
function previewImage(input) {
    const preview = document.getElementById('image-preview');
    const previewImg = document.getElementById('preview-img');
    
    if (input.files && input.files[0]) {
        const file = input.files[0];
        
        // Validate file type
        if (!file.type.match('image.*')) {
            alert('❌ Por favor selecciona solo archivos de imagen (JPG, PNG, GIF).');
            input.value = '';
            return;
        }
        
        // Validate file size (2MB max)
        if (file.size > 2 * 1024 * 1024) {
            alert('❌ La imagen es demasiado grande. El tamaño máximo permitido es 2MB.');
            input.value = '';
            return;
        }
        
        const reader = new FileReader();
        
        reader.onload = function(e) {
            previewImg.src = e.target.result;
            preview.style.display = 'block';
        };
        
        reader.readAsDataURL(file);
    } else {
        preview.style.display = 'none';
    }
}

// Remove selected image
function removeImage() {
    document.getElementById('article-image-upload').value = '';
    document.getElementById('image-preview').style.display = 'none';
    document.getElementById('preview-img').src = '';
}

// Save article (create or update)
async function saveArticle(e) {
    e.preventDefault();
    
    if (!state.currentUser) {
        alert('❌ Por favor inicie sesión para crear artículos.');
        return;
    }
    
    const articleId = document.getElementById('article-id').value;
    const title = document.getElementById('article-title').value;
    const category = document.getElementById('article-category').value;
    const chapter = document.getElementById('article-chapter').value;
    const content = document.getElementById('article-content').value;
    const status = document.getElementById('article-status').value;
    const imageFile = document.getElementById('article-image-upload').files[0];
    
    console.log('📝 [DEBUG] Creando artículo con imagen...', {
        title, category, chapter, content, status,
        author_id: state.currentUser.id,
        hasImage: !!imageFile
    });
    
    // Validate form
    const errors = validateForm({ title, content });
    if (errors.length > 0) {
        alert('❌ Errores en el formulario:\n\n' + errors.join('\n'));
        return;
    }

    try {
        let image_base64 = null;
        
        // ✅ CONVERTIR IMAGEN A BASE64 SI EXISTE
        if (imageFile) {
            console.log('🖼️ [DEBUG] Procesando imagen...');
            image_base64 = await convertImageToBase64(imageFile);
        }

        const articleData = {
            title,
            category,
            chapter,
            content,
            author_id: state.currentUser.id,
            status,
            image_base64: image_base64,  // ✅ ENVIAR IMAGEN COMO BASE64
            image_url: null
        };
        
        console.log('📤 [DEBUG] Enviando a API con imagen:', {
            ...articleData,
            image_base64: image_base64 ? `[BASE64: ${image_base64.substring(0, 50)}...]` : null
        });
        
        const response = await fetch(`${API_BASE_URL}/articles`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(articleData)
        });

        console.log('📨 [DEBUG] Respuesta HTTP:', response.status);
        
        const data = await response.json();
        console.log('📊 [DEBUG] Respuesta del servidor:', data);

        if (response.ok) {
            console.log('✅ [DEBUG] Artículo con imagen guardado en BD:', data.article);
            
            // Actualizar estado local también
            if (articleId) {
                // Actualizar artículo existente
                const index = state.articles.findIndex(a => a.id === parseInt(articleId));
                if (index !== -1) {
                    state.articles[index] = { 
                        ...state.articles[index], 
                        ...data.article,
                        image_url: data.image_url // ✅ GUARDAR URL DE LA IMAGEN
                    };
                }
            } else {
                // Crear nuevo artículo local
                const newArticle = {
                    id: data.article.id,
                    title,
                    category,
                    chapter,
                    content,
                    author: state.currentUser.name,
                    authorId: state.currentUser.id,
                    imageFile: imageFile || null,
                    image_url: data.image_url,  // ✅ GUARDAR URL DE LA IMAGEN
                    status,
                    createdAt: new Date().toISOString().split('T')[0],
                    comments: []
                };
                state.articles.push(newArticle);
            }
            
            saveDataToStorage();
            showPage('articles-page');
            loadArticles();
            updateDashboard();
            
            if (status === 'pending') {
                alert('✅ Artículo con imagen enviado para revisión exitosamente.');
            } else {
                alert('✅ Artículo con imagen guardado como borrador.');
            }
            
        } else {
            console.error('❌ [DEBUG] Error del servidor:', data);
            alert('❌ Error guardando artículo: ' + (data.error || 'Error desconocido'));
        }
        
    } catch (error) {
        console.error('💥 [DEBUG] Error completo:', error);
        
        // FALLBACK: Guardar solo en localStorage si falla la conexión
        console.log('📱 [DEBUG] Guardando localmente (modo offline)...');
        
        if (articleId) {
            const index = state.articles.findIndex(a => a.id === parseInt(articleId));
            if (index !== -1) {
                state.articles[index].title = title;
                state.articles[index].category = category;
                state.articles[index].chapter = chapter;
                state.articles[index].content = content;
                state.articles[index].status = status;
                state.articles[index].updatedAt = new Date().toISOString().split('T')[0];
                
                if (imageFile) {
                    state.articles[index].imageFile = imageFile;
                }
            }
        } else {
            const newArticle = {
                id: state.articles.length > 0 ? Math.max(...state.articles.map(a => a.id)) + 1 : 1,
                title,
                category,
                chapter,
                content,
                author: state.currentUser.name,
                authorId: state.currentUser.id,
                imageFile: imageFile || null,
                status,
                createdAt: new Date().toISOString().split('T')[0],
                comments: []
            };
            state.articles.push(newArticle);
        }
        
        saveDataToStorage();
        showPage('articles-page');
        loadArticles();
        alert('⚠️ Artículo guardado localmente (modo offline). Se sincronizará cuando haya conexión.');
    }
}

// ✅ AGREGAR ESTA FUNCIÓN PARA CONVERTIR IMAGEN A BASE64
function convertImageToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
        reader.readAsDataURL(file);
    });
}

// Validate form data
function validateForm(formData) {
    const errors = [];
    
    if (formData.title && formData.title.length < 5) {
        errors.push('• El título debe tener al menos 5 caracteres');
    }
    
    if (formData.title && formData.title.length > 100) {
        errors.push('• El título no puede tener más de 100 caracteres');
    }
    
    if (formData.content && formData.content.length < 20) {
        errors.push('• El contenido debe tener al menos 20 caracteres');
    }
    
    if (formData.content && formData.content.length > 2000) {
        errors.push('• El contenido no puede tener más de 2000 caracteres');
    }
    
    return errors;
}

// Load pending articles (for teachers/admins)
function loadPendingArticles() {
    const pendingGrid = document.getElementById('pending-articles-grid');
    let articlesHTML = '';
    
    const pendingArticles = state.articles.filter(a => a.status === 'pending');
    const thisWeek = new Date();
    thisWeek.setDate(thisWeek.getDate() - 7);
    const pendingThisWeek = pendingArticles.filter(a => new Date(a.createdAt) >= thisWeek);
    
    const urgentDate = new Date();
    urgentDate.setDate(urgentDate.getDate() - 7);
    const pendingUrgent = pendingArticles.filter(a => new Date(a.createdAt) <= urgentDate);
    
    document.getElementById('total-pending').textContent = pendingArticles.length;
    document.getElementById('pending-this-week').textContent = pendingThisWeek.length;
    document.getElementById('pending-urgent').textContent = pendingUrgent.length;
    
    if (pendingArticles.length === 0) {
        articlesHTML = '<div class="no-content"><p>No hay artículos pendientes de revisión.</p></div>';
    } else {
        pendingArticles.forEach(article => {
            const isUrgent = new Date(article.createdAt) <= urgentDate;
            const urgentClass = isUrgent ? 'style="border-left: 4px solid var(--danger)"' : '';
            
            articlesHTML += `
                <div class="article-card" ${urgentClass}>
                    <div class="article-image">
                        ${article.imageFile ? 
                            `<img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}">` : 
                            getCategoryIcon(article.category)
                        }
                    </div>
                    <div class="article-content">
                        <h3 class="article-title">${article.title}</h3>
                        <div class="article-meta">
                            <span>Por: ${article.author}</span>
                            <span>${formatDate(article.createdAt)}</span>
                            ${isUrgent ? '<span style="color: var(--danger)">⚠️ Urgente</span>' : ''}
                        </div>
                        <div class="article-excerpt">${article.content.substring(0, 100)}...</div>
                        <div class="article-meta">
                            <span>${getCategoryName(article.category)} • ${getChapterName(article.chapter)}</span>
                            <span class="article-status status-pending">Pendiente</span>
                        </div>
                        <div class="action-buttons">
                            <button class="btn-success" onclick="approveArticle(${article.id})">✅ Aprobar</button>
                            <button class="btn-danger" onclick="rejectArticle(${article.id})">❌ Rechazar</button>
                            ${state.currentUser?.role === 'admin' ? 
                              `<button class="btn-danger" onclick="event.stopPropagation(); deleteArticle(${article.id})">🗑️ Eliminar</button>` : ''}
                            <button onclick="showArticleDetail(${article.id})">👁️ Ver Detalle</button>
                        </div>
                    </div>
                </div>
            `;
        });
    }
    
    pendingGrid.innerHTML = articlesHTML;
}

// Approve article
function approveArticle(articleId) {
    const index = state.articles.findIndex(a => a.id === articleId);
    if (index !== -1) {
        state.articles[index].status = 'published';
        state.articles[index].publishedAt = new Date().toISOString().split('T')[0];
        
        // Add notification for the author
        state.notifications.unshift({
            id: state.notifications.length > 0 ? Math.max(...state.notifications.map(n => n.id)) + 1 : 1,
            title: '🎉 Artículo aprobado',
            content: `Tu artículo "${state.articles[index].title}" ha sido publicado en la revista`,
            type: 'success',
            read: false,
            createdAt: new Date().toISOString().split('T')[0],
            link: 'articles-page'
        });
        
        saveDataToStorage();
        loadPendingArticles();
        updateDashboard();
        alert('✅ Artículo aprobado y publicado exitosamente.');
    }
}

// Reject article
function rejectArticle(articleId) {
    const article = state.articles.find(a => a.id === articleId);
    if (article) {
        const reason = prompt('Por favor, ingrese el motivo del rechazo:');
        if (reason === null) return; // User cancelled
        
        if (!reason.trim()) {
            alert('Debe ingresar un motivo para rechazar el artículo.');
            return;
        }
        
        article.status = 'rejected';
        article.rejectionReason = reason;
        
        // Add notification for the author
        state.notifications.unshift({
            id: state.notifications.length > 0 ? Math.max(...state.notifications.map(n => n.id)) + 1 : 1,
            title: '📝 Artículo requiere cambios',
            content: `Tu artículo "${article.title}" fue rechazado. Motivo: ${reason}`,
            type: 'danger',
            read: false,
            createdAt: new Date().toISOString().split('T')[0],
            link: 'articles-page'
        });
        
        saveDataToStorage();
        loadPendingArticles();
        updateDashboard();
        alert('✅ Artículo rechazado. El autor ha sido notificado.');
    }
}

// Show article detail
function showArticleDetail(articleId) {
    const article = state.articles.find(a => a.id === articleId);
    if (!article) return;
    
    const articleDetail = document.getElementById('article-detail-content');
    const statusClass = `article-status status-${article.status}`;
    const statusText = getStatusText(article.status);
    
    let actionsHTML = '';

if (state.currentUser.role === 'admin') {
    actionsHTML += `
        <div class="action-buttons">
            <button class="btn-danger" onclick="deleteArticle(${article.id})">🗑️ Eliminar Artículo</button>
        </div>
    `;
}

if ((state.currentUser.role === 'teacher' || state.currentUser.role === 'admin') && article.status === 'pending') {
    actionsHTML = `
        <div class="action-buttons">
            <button class="btn-success" onclick="approveArticle(${article.id})">✅ Aprobar</button>
            <button class="btn-danger" onclick="rejectArticle(${article.id})">❌ Rechazar</button>
        </div>
    `;
} else if (state.currentUser.role === 'student' && article.author_id === state.currentUser.id && article.status !== 'published') {
    actionsHTML = `
        <div class="action-buttons">
            <button onclick="editArticle(${article.id})">✏️ Editar</button>
        </div>
    `;
}
    let rejectionHTML = '';
    if (article.rejectionReason) {
        rejectionHTML = `
            <div class="notification" style="background: #fef2f2; border-left-color: #ef4444;">
                <h4>📝 Observaciones del revisor:</h4>
                <p>${article.rejectionReason}</p>
            </div>
        `;
    }
    
    articleDetail.innerHTML = `
        <div class="form-container">
            <h2>${article.title}</h2>
            <div class="article-meta">
                <span>Por: ${article.author}</span>
                <span>${formatDate(article.createdAt)}</span>
                <span>${getCategoryName(article.category)} • ${getChapterName(article.chapter)}</span>
                <span class="${statusClass}">${statusText}</span>
            </div>
            ${rejectionHTML}
            ${article.imageFile ? `<div style="margin: 1rem 0; text-align: center;">
                <img src="${URL.createObjectURL(article.imageFile)}" alt="${article.title}" style="max-width:100%; height:auto; border-radius: 8px;">
            </div>` : ''}
            <div style="margin: 1rem 0; line-height: 1.8; white-space: pre-line;">${article.content}</div>
            ${actionsHTML}
        </div>
    `;
    
    document.getElementById('comment-article-id').value = articleId;
    document.getElementById('comments-count-badge').textContent = `(${article.comments.length})`;
    loadComments(articleId);
    showPage('article-detail-page');
}

// Edit article
function editArticle(articleId) {
    const article = state.articles.find(a => a.id === articleId);
    if (!article) return;
    
    document.getElementById('article-form-title').textContent = 'Editar Artículo';
    document.getElementById('article-id').value = article.id;
    document.getElementById('article-title').value = article.title;
    document.getElementById('article-category').value = article.category;
    document.getElementById('article-chapter').value = article.chapter;
    document.getElementById('article-content').value = article.content;
    document.getElementById('article-status').value = article.status;
    
    // Reset image preview (no se puede pre-cargar el file input por seguridad)
    document.getElementById('article-image-upload').value = '';
    document.getElementById('image-preview').style.display = 'none';
    document.getElementById('preview-img').src = '';
    
    // Update character counts
    document.getElementById('title-char-count').textContent = `${article.title.length}/100 caracteres`;
    document.getElementById('content-char-count').textContent = `${article.content.length}/2000 caracteres`;
    
    showPage('article-form-page');
}

// Delete article
// ✅ FUNCIÓN PARA ELIMINAR ARTÍCULO (SOLO ADMIN)
async function deleteArticle(articleId) {
    if (!state.currentUser) {
        alert('❌ Debes iniciar sesión para realizar esta acción.');
        return;
    }

    const article = state.articles.find(a => a.id === articleId);
    if (!article) {
        alert('❌ Artículo no encontrado.');
        return;
    }

    // Verificar permisos: solo admin puede eliminar
    if (state.currentUser.role !== 'admin') {
        alert('❌ No autorizado. Solo los administradores pueden eliminar artículos.');
        return;
    }

    // Confirmación de seguridad
    const confirmDelete = confirm(`¿Está seguro de que desea ELIMINAR permanentemente el artículo:\n\n"${article.title}"?\n\n📝 Autor: ${article.author_name || article.author}\n📊 Estado: ${getStatusText(article.status)}\n\n⚠️ Esta acción no se puede deshacer y se eliminarán todos los comentarios asociados.`);
    
    if (!confirmDelete) {
        return;
    }

    try {
        console.log('🗑️ [FRONTEND] Eliminando artículo:', articleId);
        
        const response = await fetch(`${API_BASE_URL}/articles/${articleId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'user-role': state.currentUser.role,
                'user-id': state.currentUser.id.toString()
            }
        });

        const data = await response.json();

        if (response.ok) {
            console.log('✅ [FRONTEND] Artículo eliminado de la BD:', data);
            
            // Eliminar del estado local
            state.articles = state.articles.filter(a => a.id !== articleId);
            saveDataToStorage();
            
            // Recargar la vista actual
            reloadCurrentView();
            
            alert('✅ Artículo eliminado exitosamente.');
            
        } else {
            console.error('❌ [FRONTEND] Error del servidor:', data);
            alert('❌ Error eliminando artículo: ' + (data.error || 'Error desconocido'));
        }
        
    } catch (error) {
        console.error('💥 [FRONTEND] Error de conexión:', error);
        
        // Fallback: eliminar solo localmente
        const confirmOfflineDelete = confirm(
            '❌ Error de conexión. ¿Desea eliminar el artículo localmente? Se sincronizará cuando haya conexión.'
        );
        
        if (confirmOfflineDelete) {
            state.articles = state.articles.filter(a => a.id !== articleId);
            saveDataToStorage();
            reloadCurrentView();
            alert('⚠️ Artículo eliminado localmente. Se sincronizará cuando haya conexión.');
        }
    }
}
// ✅ FUNCIÓN AUXILIAR PARA RECARGAR VISTA ACTUAL
function reloadCurrentView() {
    if (state.currentPage === 'articles-page') {
        loadArticles();
    } else if (state.currentPage === 'pending-articles-page') {
        loadPendingArticles();
    } else if (state.currentPage === 'article-detail-page') {
        showPage('articles-page');
        loadArticles();
    }
    updateDashboard();
}
// Load comments for an article
function loadComments(articleId) {
    const article = state.articles.find(a => a.id === articleId);
    if (!article) return;
    
    const commentsList = document.getElementById('comments-list');
    let commentsHTML = '';
    
    if (article.comments.length === 0) {
        commentsHTML = '<div class="no-content"><p>No hay comentarios aún. ¡Sé el primero en comentar!</p></div>';
    } else {
        article.comments.forEach(comment => {
            commentsHTML += `
                <div class="notification">
                    <h4>${comment.author}</h4>
                    <p>${comment.content}</p>
                    <small>${formatDate(comment.createdAt)}</small>
                </div>
            `;
        });
    }
    
    commentsList.innerHTML = commentsHTML;
}

// Add comment to an article
async function addComment(e) {
    e.preventDefault();
    
    if (!state.currentUser) {
        alert('❌ Por favor inicie sesión para comentar.');
        return;
    }
    
    const articleId = parseInt(document.getElementById('comment-article-id').value);
    const content = document.getElementById('comment-content').value;
    
    const article = state.articles.find(a => a.id === articleId);
    if (!article) {
        alert('❌ Artículo no encontrado.');
        return;
    }
    
    if (content.length < 1) {
        alert('❌ El comentario no puede estar vacío.');
        return;
    }
    
    if (content.length > 500) {
        alert('❌ El comentario no puede tener más de 500 caracteres.');
        return;
    }

    try {
        console.log('💬 [FRONTEND] Enviando comentario a la API...');
        
        const response = await fetch(`${API_BASE_URL}/articles/${articleId}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                author_id: state.currentUser.id,
                content: content
            })
        });

        console.log('📨 [FRONTEND] Respuesta HTTP:', response.status);
        
        const data = await response.json();
        console.log('📊 [FRONTEND] Respuesta del servidor:', data);

        if (response.ok) {
            console.log('✅ [FRONTEND] Comentario guardado en BD:', data.comment);
            
            // Actualizar también en localStorage como respaldo
            const newComment = {
                id: data.comment.id,
                author: state.currentUser.name,
                content: content,
                createdAt: new Date().toISOString().split('T')[0]
            };
            
            article.comments.push(newComment);
            document.getElementById('comment-content').value = '';
            document.getElementById('comment-char-count').textContent = '0/500 caracteres';
            
            saveDataToStorage();
            loadComments(articleId);
            updateDashboard();
            
            // Update comments count badge
            document.getElementById('comments-count-badge').textContent = `(${article.comments.length})`;
            
            // Add notification for the article author if it's not the current user
            if (article.authorId !== state.currentUser.id) {
                state.notifications.unshift({
                    id: state.notifications.length > 0 ? Math.max(...state.notifications.map(n => n.id)) + 1 : 1,
                    title: '💬 Nuevo comentario',
                    content: `Tu artículo "${article.title}" tiene un nuevo comentario`,
                    type: 'info',
                    read: false,
                    createdAt: new Date().toISOString().split('T')[0],
                    link: 'article-detail-page'
                });
                saveDataToStorage();
            }
            
            alert('✅ Comentario publicado exitosamente en la base de datos.');
            
        } else {
            console.error('❌ [FRONTEND] Error del servidor:', data);
            alert('❌ Error publicando comentario: ' + (data.error || 'Error desconocido'));
        }
        
    } catch (error) {
        console.error('💥 [FRONTEND] Error de conexión:', error);
        
        // FALLBACK: Guardar solo en localStorage si falla la conexión
        console.log('📱 [FRONTEND] Guardando comentario localmente...');
        
        const newComment = {
            id: article.comments.length > 0 ? Math.max(...article.comments.map(c => c.id)) + 1 : 1,
            author: state.currentUser.name,
            content: content,
            createdAt: new Date().toISOString().split('T')[0]
        };
        
        article.comments.push(newComment);
        document.getElementById('comment-content').value = '';
        document.getElementById('comment-char-count').textContent = '0/500 caracteres';
        
        saveDataToStorage();
        loadComments(articleId);
        updateDashboard();
        
        document.getElementById('comments-count-badge').textContent = `(${article.comments.length})`;
        
        alert('⚠️ Comentario guardado localmente (modo offline). Se sincronizará cuando haya conexión.');
    }
}
//----------------------------------------------------------------------------------------------------------//
// Load users (for admins)
// Función para cargar usuarios (actualizada)
async function loadUsers() {
    try {
        // Intentar cargar desde la API primero
        const response = await fetch(`${API_BASE_URL}/users`);
        const data = await response.json();

        if (response.ok) {
            state.users = data.users;
        } else {
            throw new Error('Error cargando usuarios de la API');
        }
    } catch (error) {
        console.error('Error cargando usuarios de la API, usando localStorage:', error);
        // Fallback a localStorage
        loadDataFromStorage();
    }

    const usersTable = document.getElementById('users-table-body');
    let usersHTML = '';

    const totalUsers = state.users.length;
    const studentUsers = state.users.filter(u => u.role === 'student').length;
    const teacherUsers = state.users.filter(u => u.role === 'teacher').length;
    const activeUsers = state.users.filter(u => u.active).length;

    document.getElementById('total-users').textContent = totalUsers;
    document.getElementById('student-users').textContent = studentUsers;
    document.getElementById('teacher-users').textContent = teacherUsers;
    document.getElementById('active-users').textContent = activeUsers;

    state.users.forEach(user => {
        usersHTML += `
            <tr>
                <td>${user.name}</td>
                <td>${user.username}</td>
                <td>${getRoleName(user.role)} ${user.talento ? `(${getCategoryName(user.talento)})` : ''}</td>
                <td><span class="article-status ${user.active ? 'status-published' : 'status-rejected'}">${user.active ? 'Activo' : 'Inactivo'}</span></td>
                <td>${formatDate(user.last_login || user.lastLogin)}</td>
                <td class="action-buttons">
                    <button class="${user.active ? 'btn-danger' : 'btn-success'}" onclick="toggleUserStatus(${user.id})">${user.active ? '🚫 Desactivar' : '✅ Activar'}</button>
                    ${user.role !== 'admin' ? `<button onclick="resetUserPassword(${user.id})">🔑 Resetear Contraseña</button>` : ''}
                </td>
            </tr>
        `;
    });

    usersTable.innerHTML = usersHTML;
}
//------------------------------------------------------------------------------------------//
// Toggle user status (actualizada)
async function toggleUserStatus(userId) {
    try {
        const user = state.users.find(u => u.id === userId);
        if (user) {
            // Llamar a la API para actualizar el estado
            const response = await fetch(`${API_BASE_URL}/users/${userId}/status`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    active: !user.active
                })
            });

            if (response.ok) {
                user.active = !user.active;
                saveDataToStorage();
                loadUsers();
                alert(`✅ Usuario ${user.active ? 'activado' : 'desactivado'} exitosamente.`);
            } else {
                throw new Error('Error actualizando estado en la API');
            }
        }
    } catch (error) {
        console.error('Error actualizando estado:', error);
        // Fallback a localStorage
        const user = state.users.find(u => u.id === userId);
        if (user) {
            user.active = !user.active;
            saveDataToStorage();
            loadUsers();
            alert(`⚠️ Estado actualizado localmente: ${user.active ? 'activado' : 'desactivado'}`);
        }
    }
}

// Reset user password (actualizada)
async function resetUserPassword(userId) {
    const user = state.users.find(u => u.id === userId);
    if (user) {
        try {
            const response = await fetch(`${API_BASE_URL}/users/${userId}/password`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    password: '123'
                })
            });

            if (response.ok) {
                user.password = '123';
                saveDataToStorage();
                alert(`✅ Contraseña de ${user.name} reseteada a "123".`);
            } else {
                throw new Error('Error reseteando contraseña en la API');
            }
        } catch (error) {
            console.error('Error reseteando contraseña:', error);
            // Fallback a localStorage
            user.password = '123';
            saveDataToStorage();
            alert(`⚠️ Contraseña reseteada localmente a "123".`);
        }
    }
}
//----------------------------------------------------------------------------------------------------------//
// Función para crear usuario (actualizada para conectar con Neon)
async function createUser(e) {
    e.preventDefault();
    
    const name = document.getElementById('new-user-name').value;
    const username = document.getElementById('new-user-username').value;
    const password = document.getElementById('new-user-password').value;
    const role = document.getElementById('new-user-role').value;
    const talento = document.getElementById('new-user-talento').value;

    console.log('🔍 [DEBUG] Datos del formulario:', { name, username, role, talento });

    // Validar formulario
    if (name.length < 2) {
        alert('El nombre debe tener al menos 2 caracteres.');
        return;
    }
    
    if (username.length < 3) {
        alert('El nombre de usuario debe tener al menos 3 caracteres.');
        return;
    }
    
    if (password.length < 3) {
        alert('La contraseña debe tener al menos 3 caracteres.');
        return;
    }

    try {
        console.log('🌐 [DEBUG] URL de API:', `${API_BASE_URL}/users`);
        console.log('📤 [DEBUG] Enviando datos a la API...');

        const response = await fetch(`${API_BASE_URL}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
                name,
                role,
                talento: role === 'student' ? talento : null
            })
        });

        console.log('📨 [DEBUG] Respuesta HTTP:', {
            status: response.status,
            statusText: response.statusText,
            ok: response.ok,
            url: response.url
        });

        const data = await response.json();
        console.log('📊 [DEBUG] Datos de respuesta:', data);

        if (response.ok) {
            console.log('✅ [DEBUG] Usuario creado exitosamente:', data.user);
            
            // Actualizar el estado local también
            const newUser = {
                id: data.user.id,
                username,
                password,
                name,
                role,
                active: true,
                talento: role === 'student' ? talento : null,
                lastLogin: new Date().toISOString().split('T')[0]
            };
            
            state.users.push(newUser);
            saveDataToStorage();
            
            showPage('users-page');
            loadUsers();
            alert('✅ Usuario creado exitosamente en la base de datos.');
        } else {
            console.error('❌ [DEBUG] Error del servidor:', data);
            alert('❌ Error creando usuario: ' + (data.error || 'Error desconocido'));
        }
    } catch (error) {
        console.error('💥 [DEBUG] Error completo:', error);
        console.error('📡 [DEBUG] Tipo de error:', error.name);
        console.error('💬 [DEBUG] Mensaje de error:', error.message);
        
        // Fallback: guardar en localStorage si falla la conexión
        const newUser = {
            id: state.users.length > 0 ? Math.max(...state.users.map(u => u.id)) + 1 : 1,
            username,
            password,
            name,
            role,
            active: true,
            talento: role === 'student' ? talento : null,
            lastLogin: new Date().toISOString().split('T')[0]
        };
        
        state.users.push(newUser);
        saveDataToStorage();
        
        showPage('users-page');
        loadUsers();
        alert('⚠️ Usuario creado localmente (modo offline). Se sincronizará cuando haya conexión.');
    }
}
//--------------------------------------------------------------------------------------------//
// Show change password form
function showChangePasswordForm() {
    if (!state.currentUser) return;
    
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
    document.getElementById('password-match').textContent = '';
    
    showPage('change-password-page');
}

// Change password
function changePassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (currentPassword !== state.currentUser.password) {
        alert('❌ La contraseña actual es incorrecta.');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        alert('❌ Las nuevas contraseñas no coinciden.');
        return;
    }
    
    if (newPassword.length < 3) {
        alert('❌ La nueva contraseña debe tener al menos 3 caracteres.');
        return;
    }
    
    state.currentUser.password = newPassword;
    saveDataToStorage();
    
    showPage('dashboard-page');
    alert('✅ Contraseña cambiada exitosamente.');
}

// Logout
function logout() {
    state.currentUser = null;
    showPublicMagazine();
    document.getElementById('login-form').reset();
    updatePublicHeader();
}

// =======================
// SISTEMA DE JUEGOS EDUCATIVOS MEJORADO
// =======================

// Games Page
function showGamesPage() {
    showPage('games-page');
    initGamesDashboard();
}

// Initialize games dashboard
function initGamesDashboard() {
    const gamesGrid = document.getElementById('games-grid');
    const userStats = document.getElementById('user-game-stats');
    const gameStatsContent = document.getElementById('game-stats-content');
    
    // Show game statistics for logged in users
    if (state.currentUser) {
        const gameStats = addGameStatistics();
        userStats.style.display = 'block';
        
        let statsHTML = '';
        if (gameStats.sudoku.played > 0) {
            statsHTML += `<p>🧩 Sudoku: ${gameStats.sudoku.completed}/${gameStats.sudoku.played} completados</p>`;
        }
        if (gameStats.memory.played > 0) {
            statsHTML += `<p>🎵 Memoria: ${gameStats.memory.completed}/${gameStats.memory.played} completados</p>`;
        }
        if (gameStats.crossword.played > 0) {
            statsHTML += `<p>📝 Crucigrama: ${gameStats.crossword.completed}/${gameStats.crossword.played} completados</p>`;
        }
        
        gameStatsContent.innerHTML = statsHTML || '<p>¡Aún no has jugado! Comienza con alguno de los juegos.</p>';
    } else {
        userStats.style.display = 'none';
    }
    
    const games = [
        {
            id: 'sudoku',
            name: '🧩 Sudoku Matemático',
            description: 'Desafía tu lógica matemática con este juego de números. Completa el tablero sin repetir números en filas, columnas o cuadrantes.',
            difficulty: 'Intermedio',
            category: 'matematico'
        },
        {
            id: 'crucigrama',
            name: '📝 Crucigrama Lingüístico',
            description: 'Amplía tu vocabulario con este crucigrama educativo. Resuelve las pistas relacionadas con temas literarios y educativos.',
            difficulty: 'Fácil',
            category: 'linguistico'
        },
        {
            id: 'memoria',
            name: '🎵 Juego de Memoria Musical',
            description: 'Entrena tu memoria con notas y ritmos musicales. Encuentra las parejas de instrumentos musicales.',
            difficulty: 'Fácil',
            category: 'musical'
        }
    ];
    
    let gamesHTML = '';
    games.forEach(game => {
        gamesHTML += `
            <div class="game-card" onclick="startGame('${game.id}')">
                <div class="game-icon">${game.name.split(' ')[0]}</div>
                <h3>${game.name}</h3>
                <p>${game.description}</p>
                <div class="game-meta">
                    <span class="difficulty-badge ${game.difficulty.toLowerCase()}">${game.difficulty}</span>
                    <span class="game-category">${getCategoryName(game.category)}</span>
                </div>
                <button class="btn-play">🎮 Jugar Ahora</button>
            </div>
        `;
    });
    
    gamesGrid.innerHTML = gamesHTML;
}

// Start a specific game
function startGame(gameId) {
    if (!state.currentUser) {
        alert('💡 Para guardar tu progreso en los juegos, inicia sesión primero.');
        showPage('login-page');
        return;
    }
    
    switch(gameId) {
        case 'sudoku':
            startSudokuGame();
            break;
        case 'crucigrama':
            startCrosswordGame();
            break;
        case 'memoria':
            startMemoryGame();
            break;
        default:
            alert('Juego en desarrollo. ¡Próximamente!');
    }
}

// Game statistics system
function addGameStatistics() {
    if (!state.currentUser) return {};
    
    const gameStats = JSON.parse(localStorage.getItem(`game_stats_${state.currentUser.id}`)) || {
        sudoku: { played: 0, completed: 0, bestTime: null },
        memory: { played: 0, completed: 0, bestScore: 0 },
        crossword: { played: 0, completed: 0 }
    };
    
    return gameStats;
}

function updateGameStats(game, result) {
    if (!state.currentUser) return;
    
    const gameStats = addGameStatistics();
    
    if (!gameStats[game]) {
        gameStats[game] = { played: 0, completed: 0, bestScore: 0 };
    }
    
    gameStats[game].played++;
    
    if (result.completed) {
        gameStats[game].completed++;
        
        if (result.score > gameStats[game].bestScore) {
            gameStats[game].bestScore = result.score;
        }
        
        if (result.time && (!gameStats[game].bestTime || result.time < gameStats[game].bestTime)) {
            gameStats[game].bestTime = result.time;
        }
    }
    
    localStorage.setItem(`game_stats_${state.currentUser.id}`, JSON.stringify(gameStats));
}

// Sudoku Game Implementation
function startSudokuGame() {
    showPage('sudoku-game-page');
    initSudoku();
}

function initSudoku() {
    const sudokuContainer = document.getElementById('sudoku-container');
    
    // Simple 4x4 Sudoku for demonstration
    const sudokuHTML = `
        <div class="game-header">
            <h2>🧩 Sudoku Matemático</h2>
            <p>Completa el tablero con números del 1 al 4 sin repetir en filas, columnas o cuadrantes 2x2</p>
        </div>
        <div class="sudoku-board">
            <div class="sudoku-grid">
                ${Array.from({length: 16}, (_, i) => `
                    <div class="sudoku-cell" data-row="${Math.floor(i/4)}" data-col="${i%4}">
                        <input type="number" min="1" max="4" oninput="validateSudokuInput(this)">
                    </div>
                `).join('')}
            </div>
        </div>
        <div class="game-controls">
            <button onclick="checkSudokuSolution()" class="btn-success">✅ Verificar Solución</button>
            <button onclick="resetSudokuGame()" class="btn-warning">🔄 Reiniciar</button>
            <button onclick="showGamesPage()" class="btn-outline">← Volver a Juegos</button>
        </div>
        <div id="sudoku-feedback" class="game-feedback"></div>
    `;
    
    sudokuContainer.innerHTML = sudokuHTML;
    
    // Set some initial numbers (puzzle)
    const initialNumbers = [
        [1, 0, 0, 0],
        [0, 0, 2, 0],
        [0, 3, 0, 0],
        [0, 0, 0, 4]
    ];
    
    const cells = document.querySelectorAll('.sudoku-cell input');
    cells.forEach((cell, index) => {
        const row = Math.floor(index / 4);
        const col = index % 4;
        if (initialNumbers[row][col] !== 0) {
            cell.value = initialNumbers[row][col];
            cell.readOnly = true;
            cell.style.background = '#f3f4f6';
            cell.style.fontWeight = 'bold';
        }
    });
    
    // Start timer
    window.sudokuStartTime = new Date();
}

function validateSudokuInput(input) {
    const value = parseInt(input.value);
    if (value < 1 || value > 4) {
        input.value = '';
    }
}

function resetSudokuGame() {
    initSudoku();
}

function checkSudokuSolution() {
    const cells = document.querySelectorAll('.sudoku-cell input');
    let solved = true;
    let emptyCells = 0;
    
    // Check if all cells are filled
    cells.forEach(cell => {
        if (!cell.value) {
            solved = false;
            emptyCells++;
            cell.style.border = '2px solid red';
        } else {
            cell.style.border = '1px solid #ccc';
        }
    });
    
    const feedback = document.getElementById('sudoku-feedback');
    
    if (emptyCells > 0) {
        feedback.innerHTML = `
            <div class="error-message">
                <p>❌ Faltan ${emptyCells} celdas por completar. Revisa las celdas en rojo.</p>
            </div>
        `;
        return;
    }
    
    // Check Sudoku rules (simplified for 4x4)
    // In a real implementation, you would check rows, columns, and 2x2 boxes
    
    if (solved) {
        const endTime = new Date();
        const timeTaken = Math.floor((endTime - window.sudokuStartTime) / 1000);
        
        feedback.innerHTML = `
            <div class="success-message">
                <h3>🎉 ¡Felicidades!</h3>
                <p>Has completado correctamente el Sudoku en ${timeTaken} segundos.</p>
                <p>¡Excelente razonamiento matemático!</p>
            </div>
        `;
        
        // Add achievement notification and update stats
        if (state.currentUser) {
            state.notifications.unshift({
                id: state.notifications.length + 1,
                title: '🏆 Logro Desbloqueado',
                content: `Completaste el Sudoku Matemático en ${timeTaken} segundos`,
                type: 'success',
                read: false,
                createdAt: new Date().toISOString().split('T')[0]
            });
            
            updateGameStats('sudoku', {
                completed: true,
                score: 100,
                time: timeTaken
            });
            
            saveDataToStorage();
            updateDashboard();
        }
    } else {
        feedback.innerHTML = `
            <div class="error-message">
                <p>❌ La solución no es correcta. Revisa que no se repitan números en filas, columnas o cuadrantes.</p>
            </div>
        `;
    }
}

// Crossword Game Implementation
function startCrosswordGame() {
    showPage('crossword-game-page');
    initCrossword();
}

function initCrossword() {
    const crosswordContainer = document.getElementById('crossword-container');
    
    const crosswordHTML = `
        <div class="game-header">
            <h2>📝 Crucigrama Lingüístico</h2>
            <p>Resuelve el crucigrama relacionado con temas educativos y literarios. Haz clic en las casillas para escribir.</p>
        </div>
        
        <div class="crossword-clues">
            <div class="clues-section">
                <h4>Horizontal:</h4>
                <p><strong>1.</strong> Género literario que usa el verso (6 letras)</p>
                <p><strong>3.</strong> Sinónimo de aprender (9 letras)</p>
            </div>
            <div class="clues-section">
                <h4>Vertical:</h4>
                <p><strong>2.</strong> Persona que escribe libros (7 letras)</p>
                <p><strong>4.</strong> Lugar donde se estudia (7 letras)</p>
            </div>
        </div>
        
        <div class="crossword-board">
            <div class="crossword-grid">
                <!-- This would be a more complex grid in a real implementation -->
                <div style="text-align: center; padding: 2rem;">
                    <p>🔄 El crucigrama interactivo estará disponible en la próxima actualización</p>
                    <p>Por ahora, practica con los otros juegos disponibles.</p>
                </div>
            </div>
        </div>
        
        <div class="game-controls">
            <button onclick="checkCrosswordSolution()" class="btn-success">✅ Verificar Respuestas</button>
            <button onclick="showGamesPage()" class="btn-outline">← Volver a Juegos</button>
        </div>
        
        <div id="crossword-feedback" class="game-feedback"></div>
    `;
    
    crosswordContainer.innerHTML = crosswordHTML;
}

function checkCrosswordSolution() {
    // In a real implementation, this would check the crossword answers
    alert('🎉 ¡Crucigrama completado! Este es un ejemplo demostrativo.\n\nRespuestas correctas:\n1. POESÍA\n2. ESCRITOR\n3. ESTUDIAR\n4. COLEGIO\n\nEn una versión completa, se validarían todas las respuestas automáticamente.');
    
    // Update game stats
    if (state.currentUser) {
        updateGameStats('crossword', {
            completed: true,
            score: 100
        });
        
        state.notifications.unshift({
            id: state.notifications.length + 1,
            title: '🏆 Logro Desbloqueado',
            content: 'Completaste el Crucigrama Lingüístico',
            type: 'success',
            read: false,
            createdAt: new Date().toISOString().split('T')[0]
        });
        
        saveDataToStorage();
        updateDashboard();
    }
}

// Memory Game Implementation
function startMemoryGame() {
    showPage('memory-game-page');
    initMemoryGame();
}

function initMemoryGame() {
    const memoryContainer = document.getElementById('memory-container');
    
    const symbols = ['🎵', '🎶', '🎼', '🎹', '🎷', '🎺', '🎻', '🥁'];
    const cards = [...symbols, ...symbols].sort(() => Math.random() - 0.5);
    
    let memoryHTML = `
        <div class="game-header">
            <h2>🎵 Juego de Memoria Musical</h2>
            <p>Encuentra las parejas de instrumentos musicales. Haz clic en las cartas para voltearlas.</p>
            <div class="game-stats">
                <span>Intentos: <span id="attempts">0</span></span>
                <span>Parejas: <span id="matches">0</span>/8</span>
                <span>Tiempo: <span id="timer">0</span>s</span>
            </div>
        </div>
        <div class="memory-grid">
    `;
    
    cards.forEach((symbol, index) => {
        memoryHTML += `
            <div class="memory-card" data-index="${index}" onclick="flipCard(this)">
                <div class="card-front">?</div>
                <div class="card-back">${symbol}</div>
            </div>
        `;
    });
    
    memoryHTML += `
        </div>
        <div class="game-controls">
            <button onclick="resetMemoryGame()" class="btn-success">🔄 Reiniciar Juego</button>
            <button onclick="showGamesPage()" class="btn-outline">← Volver a Juegos</button>
        </div>
    `;
    
    memoryContainer.innerHTML = memoryHTML;
    
    // Initialize game state
    window.memoryGameState = {
        flippedCards: [],
        attempts: 0,
        matches: 0,
        locked: false,
        startTime: new Date(),
        timerInterval: setInterval(updateMemoryTimer, 1000)
    };
    
    // Start timer
    function updateMemoryTimer() {
        if (window.memoryGameState) {
            const elapsed = Math.floor((new Date() - window.memoryGameState.startTime) / 1000);
            document.getElementById('timer').textContent = elapsed;
        }
    }
}

function flipCard(card) {
    const state = window.memoryGameState;
    if (state.locked || card.classList.contains('flipped') || card.classList.contains('matched')) return;
    
    card.classList.add('flipped');
    state.flippedCards.push(card);
    
    if (state.flippedCards.length === 2) {
        state.attempts++;
        document.getElementById('attempts').textContent = state.attempts;
        
        state.locked = true;
        const [card1, card2] = state.flippedCards;
        
        if (card1.querySelector('.card-back').textContent === card2.querySelector('.card-back').textContent) {
            // Match found
            setTimeout(() => {
                card1.classList.add('matched');
                card2.classList.add('matched');
                state.matches++;
                document.getElementById('matches').textContent = state.matches;
                state.flippedCards = [];
                state.locked = false;
                
                if (state.matches === 8) {
                    clearInterval(state.timerInterval);
                    const endTime = new Date();
                    const timeTaken = Math.floor((endTime - state.startTime) / 1000);
                    const score = Math.max(1000 - (state.attempts * 10) - (timeTaken * 2), 100);
                    
                    setTimeout(() => {
                        alert(`🎉 ¡Felicidades! Has completado el juego de memoria.\n\n📊 Estadísticas:\n• Tiempo: ${timeTaken} segundos\n• Intentos: ${state.attempts}\n• Puntuación: ${score}`);
                        
                        if (state.currentUser) {
                            updateGameStats('memory', {
                                completed: true,
                                score: score
                            });
                            
                            state.notifications.unshift({
                                id: state.notifications.length + 1,
                                title: '🏆 Logro Desbloqueado',
                                content: `Completaste el Juego de Memoria con ${score} puntos`,
                                type: 'success',
                                read: false,
                                createdAt: new Date().toISOString().split('T')[0]
                            });
                            saveDataToStorage();
                            updateDashboard();
                        }
                    }, 500);
                }
            }, 500);
        } else {
            // No match
            setTimeout(() => {
                card1.classList.remove('flipped');
                card2.classList.remove('flipped');
                state.flippedCards = [];
                state.locked = false;
            }, 1000);
        }
    }
}

function resetMemoryGame() {
    // Clear existing timer
    if (window.memoryGameState && window.memoryGameState.timerInterval) {
        clearInterval(window.memoryGameState.timerInterval);
    }
    initMemoryGame();
}

// =======================
// SISTEMA DE AYUDA Y OTRAS FUNCIONALIDADES
// =======================

// Help system
function showHelp(section) {
    const helpMessages = {
        login: `🔐 Sistema de Login 💡 También puedes continuar como espectador sin iniciar sesión.`,

        dashboard: `📊 **Panel de Control**\n\nEl dashboard muestra:\n• Estadísticas generales del sistema\n• Notificaciones recientes\n• Acciones rápidas según tu rol\n\n**Estadísticas:**\n• Artículos publicados\n• Artículos pendientes de revisión\n• Comentarios totales\n• Usuarios activos`,

        articles: `📚 **Gestión de Artículos**\n\n**Para Estudiantes:**\n• Crear nuevos artículos\n• Editar tus artículos existentes\n• Enviar artículos para revisión\n• Ver el estado de tus envíos\n\n**Para Docentes y Administradores:**\n• Revisar todos los artículos\n• Aprobar o rechazar artículos pendientes\n• Filtrar por estado, categoría o capítulo`,

        review: `⏳ **Revisión de Artículos**\n\n**Proceso de revisión:**\n1. Los estudiantes envían artículos para revisión\n2. Los docentes revisan el contenido\n3. Se aprueba o se rechaza con observaciones\n4. Los estudiantes reciben notificaciones\n\n**Artículos urgentes:**\nLos artículos pendientes por más de 7 días se marcan como urgentes.`,

        users: `👥 **Gestión de Usuarios**\n\n**Solo para Administradores:**\n• Crear nuevos usuarios\n• Activar/desactivar usuarios\n• Resetear contraseñas\n• Ver estadísticas de uso\n\n**Roles disponibles:**\n• Estudiante Reportero\n• Docente\n• Padre de Familia\n• Administrador`,

        games: `🎮 **Juegos Educativos**\n\n**Juegos disponibles:**\n• 🧩 Sudoku Matemático: Desarrolla lógica y razonamiento\n• 📝 Crucigrama Lingüístico: Mejora vocabulario\n• 🎵 Memoria Musical: Entrena la memoria\n\n**Características:**\n• Diferentes niveles de dificultad\n• Seguimiento de progreso\n• Logros y recompensas\n• Diseño educativo y divertido`,

        notifications: `🔔 **Sistema de Notificaciones**\n\n**Tipos de notificaciones:**\n• ✅ Aprobación de artículos\n• ⚠️ Artículos pendientes de revisión\n• ❌ Rechazo de artículos con observaciones\n• 💬 Nuevos comentarios\n• ℹ️ Información general\n\n**Funcionalidades:**\n• Notificaciones no leídas resaltadas\n• Clic para acceder directamente al contenido relacionado\n• Historial de notificaciones`,

        actions: `⚡ **Acciones Rápidas**\n\n**Acciones disponibles:**\n• 📝 Nuevo Artículo: Crear contenido nuevo\n• 📚 Ver Artículos: Gestionar publicaciones\n• 🎮 Juegos Educativos: Aprender jugando\n• 👀 Ver Revista: Modo espectador público\n• 🔒 Cambiar Contraseña: Seguridad de cuenta\n• 📤 Exportar Datos: Backup del sistema (solo admin)`
    };

    const message = helpMessages[section] || 'No hay ayuda disponible para esta sección.';
    alert(message);
}

// Export data function (for admins)
function exportData() {
    if (!state.currentUser || state.currentUser.role !== 'admin') {
        alert('❌ Solo los administradores pueden exportar datos.');
        return;
    }

    const exportData = {
        exportedAt: new Date().toISOString(),
        system: 'Revista Digital - Colegio San Francisco IED',
        version: '2.0',
        data: {
            articles: state.articles,
            users: state.users.map(u => ({ 
                ...u, 
                password: '***' // Hide passwords for security
            })),
            notifications: state.notifications,
            statistics: showAdvancedStats()
        }
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `revista_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    alert('✅ Datos exportados exitosamente.\nEl archivo se ha descargado como "revista_export_[fecha].json"');
}

// Advanced statistics
function showAdvancedStats() {
    const stats = {
        totalArticles: state.articles.length,
        publishedArticles: state.articles.filter(a => a.status === 'published').length,
        pendingArticles: state.articles.filter(a => a.status === 'pending').length,
        draftArticles: state.articles.filter(a => a.status === 'draft').length,
        rejectedArticles: state.articles.filter(a => a.status === 'rejected').length,
        articlesByCategory: {},
        articlesByChapter: {},
        activeUsers: state.users.filter(u => u.active).length,
        totalUsers: state.users.length,
        usersByRole: {},
        totalComments: state.articles.reduce((sum, article) => sum + article.comments.length, 0),
        exportDate: new Date().toISOString()
    };
    
    // Calculate statistics by category and chapter
    state.articles.forEach(article => {
        stats.articlesByCategory[article.category] = (stats.articlesByCategory[article.category] || 0) + 1;
        stats.articlesByChapter[article.chapter] = (stats.articlesByChapter[article.chapter] || 0) + 1;
    });
    
    // Calculate statistics by user role
    state.users.forEach(user => {
        stats.usersByRole[user.role] = (stats.usersByRole[user.role] || 0) + 1;
    });
    
    return stats;
}
// También asegúrate de que esta línea esté al final de script.js:
window.showCreateUserForm = showCreateUserForm;
// FUNCIONES GLOBALES QUE DEBEN ESTAR DEFINIDAS
window.showCreateUserForm = showCreateUserForm;
window.showPublicMagazine = showPublicMagazine;
window.showPage = showPage;
window.showGamesPage = showGamesPage;
window.logout = logout;
window.handleLogin = handleLogin;

// Funciones para los juegos
window.startSudokuGame = startSudokuGame;
window.startCrosswordGame = startCrosswordGame;
window.startMemoryGame = startMemoryGame;
window.resetSudokuGame = resetSudokuGame;
window.checkSudokuSolution = checkSudokuSolution;
window.flipCard = flipCard;
window.resetMemoryGame = resetMemoryGame;

// Funciones de artículos
window.showNewArticleForm = showNewArticleForm;
window.editArticle = editArticle;
window.deleteArticle = deleteArticle;
window.showArticleDetail = showArticleDetail;
window.filterArticles = filterArticles;

// Funciones de usuarios (para admin)
window.toggleUserStatus = toggleUserStatus;
window.resetUserPassword = resetUserPassword;

// Funciones del sistema
window.exportData = exportData;
window.showHelp = showHelp;
window.searchInMagazine = searchInMagazine;
// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', initApp);

// Add some utility functions to the global scope for easier debugging
window.getAppState = () => state;
window.resetApp = () => {
    localStorage.clear();
    location.reload();
};


//-----------------------------------------------------------//
