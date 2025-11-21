// server.js - VERSIÓN CORREGIDA Y OPTIMIZADA
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { query } = require('./database');
const { initializeDatabase } = require('./init-db');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================
// CONFIGURACIÓN
// ==========================
const allowedOrigins = [
    'https://revista-san-francisco-ied.onrender.com',
    'https://smartinez31.github.io',
    'http://localhost:5500',
    'http://127.0.0.1:5500',  // ⭐⭐ AGREGAR ESTE
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:10000',  // ⭐⭐ AGREGAR ESTE TAMBIÉN
    'http://127.0.0.1:10000'  // ⭐⭐ Y ESTE
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        console.log('🚫 Origen bloqueado por CORS:', origin);
        callback(new Error('No permitido por CORS'));
    },
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ⭐⭐ AQUÍ VAN LAS CONFIGURACIONES DE STATIC FILES - JUSTO EN ESTA POSICIÓN ⭐⭐
app.use('/images', express.static(path.join(__dirname, 'public', 'images'), {
    maxAge: '1d', // Cache por 1 día
    etag: true
}));

app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true
}));

// ==========================
// FUNCIONES AUXILIARES
// ==========================

// Agrega esto temporalmente en server.js para debug
app.get('/api/debug-images', (req, res) => {
    const imagesDir = path.join(__dirname, 'public', 'images');
    const files = fs.readdirSync(imagesDir);
    console.log('📁 Archivos en images/', files);
    res.json({ files });
});

// ✅ FUNCIÓN PARA GUARDAR IMÁGENES BASE64
// ✅ FUNCIÓN MEJORADA PARA GUARDAR IMÁGENES
async function saveBase64Image(base64Data, title) {
    try {
        console.log('🖼️ [IMAGE] Iniciando guardado de imagen...');
        
        // Crear directorio de imágenes si no existe
        const imagesDir = path.join(__dirname, 'public', 'images');
        if (!fs.existsSync(imagesDir)) {
            console.log('📁 Creando directorio images:', imagesDir);
            fs.mkdirSync(imagesDir, { recursive: true });
        }

        // Verificar que es una imagen base64 válida
        if (!base64Data || typeof base64Data !== 'string') {
            console.log('❌ [IMAGE] Datos de imagen inválidos');
            return null;
        }

        // Extraer el tipo de imagen y los datos
        const matches = base64Data.match(/^data:image\/([A-Za-z-+/]+);base64,(.+)$/);
        if (!matches || matches.length !== 3) {
            console.log('❌ [IMAGE] Formato base64 inválido');
            return null;
        }

        const imageType = matches[1].toLowerCase();
        const imageData = matches[2];
        
        // Validar tipo de imagen
        const validTypes = ['jpeg', 'jpg', 'png', 'gif', 'webp'];
        if (!validTypes.includes(imageType)) {
            console.log('❌ [IMAGE] Tipo de imagen no soportado:', imageType);
            return null;
        }

        // Convertir base64 a buffer
        const buffer = Buffer.from(imageData, 'base64');
        
        // Validar tamaño (máximo 2MB)
        if (buffer.length > 2 * 1024 * 1024) {
            console.log('❌ [IMAGE] Imagen demasiado grande:', buffer.length);
            return null;
        }

        // Generar nombre único para el archivo
        const timestamp = Date.now();
        const safeTitle = title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
        const fileExtension = imageType === 'jpeg' ? 'jpg' : imageType;
        const filename = `article_${safeTitle}_${timestamp}.${fileExtension}`;
        const filePath = path.join(imagesDir, filename);

        // Guardar archivo
        fs.writeFileSync(filePath, buffer);
        
        console.log('✅ [IMAGE] Imagen guardada exitosamente:', filename);
        console.log('📁 [IMAGE] Ruta completa:', filePath);
        
        // Retornar URL pública (RELATIVA al servidor)
        return `/images/${filename}`;
        
    } catch (error) {
        console.error('❌ [IMAGE] Error guardando imagen:', error);
        return null;
    }
}
// ✅ RUTA DE DEBUG PARA VERIFICAR IMÁGENES
app.get('/api/debug-images', (req, res) => {
    try {
        const imagesDir = path.join(__dirname, 'public', 'images');
        
        // Verificar si existe el directorio
        if (!fs.existsSync(imagesDir)) {
            return res.json({ 
                exists: false, 
                message: 'Directorio images no existe',
                path: imagesDir 
            });
        }

        // Leer archivos
        const files = fs.readdirSync(imagesDir);
        const imageFiles = files.filter(file => 
            /\.(jpg|jpeg|png|gif|webp)$/i.test(file)
        );

        console.log('📁 [DEBUG] Archivos en images/:', files);
        console.log('🖼️ [DEBUG] Imágenes encontradas:', imageFiles);

        res.json({ 
            exists: true,
            totalFiles: files.length,
            imageFiles: imageFiles,
            files: files,
            path: imagesDir
        });

    } catch (error) {
        console.error('❌ [DEBUG] Error leyendo directorio:', error);
        res.status(500).json({ error: error.message });
    }
});
// En server.js - AGREGAR ruta de debug de imágenes
app.get('/api/debug/article-images', async (req, res) => {
    try {
        const result = await query(`
            SELECT id, title, image_url 
            FROM articles 
            WHERE image_url IS NOT NULL
            ORDER BY created_at DESC
        `);
        
        console.log('🖼️ [DEBUG] Artículos con imágenes:', result.rows);
        
        res.json({
            articles_with_images: result.rows,
            image_base_url: IMAGE_BASE_URL,
            public_images_path: path.join(__dirname, 'public', 'images')
        });
        
    } catch (error) {
        console.error('❌ Error en debug de imágenes:', error);
        res.status(500).json({ error: error.message });
    }
});
// ==========================
// MIDDLEWARE PARA HEADERS DE USUARIO
// ==========================
app.use((req, res, next) => {
    // Para desarrollo: permitir headers de usuario desde el frontend
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, user-role, user-id');
    next();
});

// ==========================
// MIDDLEWARE DE LOGGING
// ==========================
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ==========================
// INICIALIZACIÓN
// ==========================
initializeDatabase()
    .then(() => console.log('✅ Base de datos inicializada correctamente'))
    .catch(err => console.error('❌ Error inicializando BD:', err));

// ==========================
// RUTAS PRINCIPALES
// ==========================

// Healthcheck
app.get('/api/health', async (req, res) => {
    try {
        await query("SELECT 1");
        return res.json({
            status: "OK",
            environment: process.env.NODE_ENV,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        return res.status(500).json({ status: "ERROR", error: err.message });
    }
});

// ==========================
// AUTENTICACIÓN
// ==========================
// En server.js - TEMPORAL para debug
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;

        console.log('🔐 [LOGIN DEBUG] Datos recibidos:', { 
            username, 
            password, 
            role,
            passwordLength: password?.length 
        });

        // DEBUG: Verificar usuario específico con todos los detalles
        const userCheck = await query(
            'SELECT username, password, role, active, length(password) as pass_length FROM users WHERE username = $1',
            [username]
        );
        
        console.log('👤 [LOGIN DEBUG] Usuario encontrado:', userCheck.rows[0]);
        
        if (userCheck.rows.length > 0) {
            const user = userCheck.rows[0];
            console.log('🔑 [LOGIN DEBUG] Comparación de contraseñas:');
            console.log('   - Contraseña recibida:', `"${password}"`, `(length: ${password?.length})`);
            console.log('   - Contraseña en BD:', `"${user.password}"`, `(length: ${user.pass_length})`);
            console.log('   - ¿Coinciden?', password === user.password);
        }

        // Consulta original
        const result = await query(
            'SELECT id, username, name, role, talento, active FROM users WHERE username=$1 AND password=$2 AND role=$3 AND active=true',
            [username, password, role]
        );

        console.log('📊 [LOGIN DEBUG] Resultado de la consulta:', result.rows);

        if (result.rows.length === 0) {
            console.log('❌ [LOGIN DEBUG] No se encontró usuario con esos criterios');
            return res.status(401).json({ error: "Credenciales incorrectas" });
        }

        await query('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=$1', [result.rows[0].id]);
        
        console.log('✅ [LOGIN DEBUG] Login exitoso para:', result.rows[0].username);
        res.json({ user: result.rows[0] });
        
    } catch (error) {
        console.error('❌ [LOGIN DEBUG] Error en login:', error);
        res.status(500).json({ error: "Error de servidor durante el login" });
    }
});
// ==========================
// ELIMINAR USUARIOS (SOLO ADMIN)
// ==========================
app.delete('/api/users/:id', async (req, res) => {
    try {
        console.log('🗑️ [DELETE USER] Intentando eliminar usuario:', req.params.id);
        
        // Obtener el usuario que hace la solicitud desde el header
        const userRole = req.headers['user-role'];
        const userId = req.headers['user-id'];
        
        console.log('👤 [DELETE USER] Administrador solicitante:', { userId, userRole });
        
        // Verificar que solo administradores pueden eliminar usuarios
        if (userRole !== 'admin') {
            console.log('🚫 [DELETE USER] Usuario no autorizado para eliminar usuarios');
            return res.status(403).json({ 
                error: "No autorizado. Solo los administradores pueden eliminar usuarios." 
            });
        }

        // ⭐⭐ EVITAR QUE EL ADMIN SE ELIMINE A SÍ MISMO ⭐⭐
        if (parseInt(req.params.id) === parseInt(userId)) {
            console.log('🚫 [DELETE USER] Intento de auto-eliminación bloqueado');
            return res.status(400).json({ 
                error: "No puedes eliminar tu propio usuario." 
            });
        }

        // Verificar que el usuario existe
        const userCheck = await query(
            'SELECT id, username, name, role FROM users WHERE id = $1',
            [req.params.id]
        );

        if (userCheck.rows.length === 0) {
            console.log('❌ [DELETE USER] Usuario no encontrado');
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const userToDelete = userCheck.rows[0];
        console.log('👤 [DELETE USER] Usuario a eliminar:', userToDelete);

        // ⭐⭐ VERIFICAR QUE NO SEA EL ÚLTIMO ADMIN ⭐⭐
        if (userToDelete.role === 'admin') {
            const adminCount = await query(
                'SELECT COUNT(*) FROM users WHERE role = $1 AND active = $2',
                ['admin', true]
            );
            
            const activeAdmins = parseInt(adminCount.rows[0].count);
            if (activeAdmins <= 1) {
                console.log('🚫 [DELETE USER] No se puede eliminar el último administrador activo');
                return res.status(400).json({ 
                    error: "No se puede eliminar el último administrador activo del sistema." 
                });
            }
        }

        // ⭐⭐ VERIFICAR QUE EL USUARIO NO TENGA ARTÍCULOS ASOCIADOS ⭐⭐
        const userArticles = await query(
            'SELECT COUNT(*) FROM articles WHERE author_id = $1',
            [req.params.id]
        );
        
        const articleCount = parseInt(userArticles.rows[0].count);
        if (articleCount > 0) {
            console.log(`📝 [DELETE USER] Usuario tiene ${articleCount} artículos asociados`);
            return res.status(400).json({ 
                error: `No se puede eliminar el usuario porque tiene ${articleCount} artículo(s) publicados. Primero elimine o transfiera los artículos.` 
            });
        }

        // Eliminar el usuario
        console.log('🗑️ [DELETE USER] Eliminando usuario de la base de datos...');
        const result = await query(
            'DELETE FROM users WHERE id = $1 RETURNING *',
            [req.params.id]
        );

        console.log('✅ [DELETE USER] Usuario eliminado exitosamente');
        res.json({ 
            success: true, 
            message: "Usuario eliminado exitosamente",
            deletedUser: result.rows[0]
        });

    } catch (err) {
        console.error('❌ [DELETE USER] Error eliminando usuario:', err.message);
        
        // Manejar error de clave foránea
        if (err.message.includes('foreign key constraint')) {
            return res.status(500).json({ 
                error: "No se puede eliminar el usuario porque tiene datos asociados (artículos, comentarios, etc.)." 
            });
        }
        
        res.status(500).json({ 
            error: "Error eliminando usuario: " + err.message 
        });
    }
});
// ==========================
// ARTÍCULOS (VERSIÓN ÚNICA CORREGIDA)
// ==========================
// ✅ RUTA CORREGIDA PARA CREAR ARTÍCULOS CON IMÁGENES
// ✅ MEJORAR RUTA DE CREAR ARTÍCULOS - VERIFICAR SESIÓN
app.post('/api/articles', async (req, res) => {
    try {
        console.log('📥 [ARTICLES] Creando artículo...');
        
        // ⭐⭐ VERIFICAR AUTENTICACIÓN DESDE HEADERS ⭐⭐
        const userRole = req.headers['user-role'];
        const userId = req.headers['user-id'];
        
        console.log('👤 [ARTICLES] Usuario desde headers:', { userId, userRole });
        
        if (!userId || !userRole) {
            return res.status(401).json({ 
                error: "No autenticado. Por favor inicie sesión." 
            });
        }
        
        const { title, category, chapter, content, status, image_base64 } = req.body;

        // Validación básica
        if (!title?.trim() || !content?.trim()) {
            return res.status(400).json({ 
                error: "Título y contenido son requeridos" 
            });
        }

        // ✅ MANEJAR IMÁGENES
        let image_url = null;
        
        if (image_base64) {
            console.log('🖼️ [ARTICLES] Procesando imagen base64...');
            image_url = await saveBase64Image(image_base64, title);
            console.log('🖼️ [ARTICLES] URL de imagen generada:', image_url);
        }

        // Determinar status y published_at
        const statusValue = status === 'published' ? 'published' : 
                           status === 'pending' ? 'pending' : 
                           status === 'rejected' ? 'rejected' : 'draft';

        const publishedAt = status === 'published' ? 'NOW()' : 'NULL';
        
        // ✅ QUERY CORREGIDA - Usar el userId de los headers
        const queryText = `
            INSERT INTO articles (title, category, chapter, content, author_id, status, image_url, published_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, ${publishedAt})
            RETURNING *
        `;

        const result = await query(queryText, [
            title.trim(),
            category,
            chapter,
            content.trim(),
            parseInt(userId), // ⭐⭐ USAR userId DE LOS HEADERS
            statusValue,
            image_url
        ]);

        console.log('✅ [ARTICLES] Artículo creado exitosamente por usuario:', userId);
        
        res.json({ 
            success: true, 
            article: result.rows[0],
            image_url: image_url 
        });

    } catch (err) {
        console.error("❌ [ARTICLES] Error creando artículo:", err.message);
        res.status(500).json({ 
            error: "Error creando artículo: " + err.message 
        });
    }
});
// OBTENER ARTÍCULOS
app.get('/api/articles', async (req, res) => {
    try {
        console.log('📚 [ARTICLES DEBUG] Solicitando todos los artículos...');
        
        const result = await query(`
            SELECT a.*, 
                   COALESCE(u.name, 'Autor Desconocido') AS author_name  -- ⭐⭐ CORRECCIÓN AQUÍ
            FROM articles a 
            LEFT JOIN users u ON a.author_id = u.id
            ORDER BY a.created_at DESC
        `);
        
        console.log('✅ [ARTICLES DEBUG] Artículos encontrados en BD:', result.rows.length);
        console.log('📋 [ARTICLES DEBUG] Detalles:', 
            result.rows.map(a => ({ 
                id: a.id, 
                title: a.title.substring(0, 30) + '...', 
                status: a.status,
                author: a.author_name  -- //⭐⭐ Ahora siempre tendrá un valor
            }))
        );
        
        res.json({ success: true, articles: result.rows });
    } catch (err) {
        console.error('❌ Error obteniendo artículos:', err);
        res.status(500).json({ error: "Error obteniendo artículos" });
    }
});
// OBTENER ARTÍCULO POR ID
app.get('/api/articles/:id', async (req, res) => {
    try {
        const result = await query(`
            SELECT a.*, u.name AS author_name
            FROM articles a LEFT JOIN users u ON a.author_id = u.id
            WHERE a.id = $1
        `, [req.params.id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Artículo no encontrado" });
        }
        
        res.json({ success: true, article: result.rows[0] });
    } catch (err) {
        console.error('❌ Error obteniendo artículo:', err);
        res.status(500).json({ error: "Error obteniendo artículo" });
    }
});
// ⭐⭐ AGREGAR RUTA PARA APROBAR ARTÍCULOS ⭐⭐
app.put('/api/articles/:id/approve', async (req, res) => {
    try {
        console.log('✅ [API] Aprobando artículo:', req.params.id);
        
        const userRole = req.headers['user-role'];
        const userId = req.headers['user-id'];
        
        // Verificar permisos
        if (userRole !== 'teacher' && userRole !== 'admin') {
            return res.status(403).json({ 
                error: "No autorizado. Solo docentes y administradores pueden aprobar artículos." 
            });
        }

        // Actualizar en la base de datos
        const result = await query(`
            UPDATE articles 
            SET status = 'published', 
                published_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1 
            RETURNING *
        `, [req.params.id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Artículo no encontrado" });
        }

        const updatedArticle = result.rows[0];
        
        console.log('✅ [API] Artículo aprobado:', updatedArticle.id);
        
        res.json({ 
            success: true, 
            article: updatedArticle,
            message: "Artículo aprobado y publicado exitosamente"
        });

    } catch (err) {
        console.error('❌ Error aprobando artículo:', err);
        res.status(500).json({ 
            error: "Error aprobando artículo: " + err.message 
        });
    }
});
// ⭐⭐ AGREGAR RUTA PARA RECHAZAR ARTÍCULOS ⭐⭐
app.put('/api/articles/:id/reject', async (req, res) => {
    try {
        const { rejection_reason } = req.body;
        const userRole = req.headers['user-role'];
        
        if (userRole !== 'teacher' && userRole !== 'admin') {
            return res.status(403).json({ 
                error: "No autorizado. Solo docentes y administradores pueden rechazar artículos." 
            });
        }

        const result = await query(`
            UPDATE articles 
            SET status = 'rejected', 
                rejection_reason = $1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $2 
            RETURNING *
        `, [rejection_reason, req.params.id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Artículo no encontrado" });
        }

        res.json({ 
            success: true, 
            article: result.rows[0],
            message: "Artículo rechazado exitosamente"
        });

    } catch (err) {
        console.error('❌ Error rechazando artículo:', err);
        res.status(500).json({ 
            error: "Error rechazando artículo: " + err.message 
        });
    }
});

// ==========================
// SISTEMA DE LIKES
// ==========================

// Obtener likes de un artículo
// En server.js - CORREGIR la ruta de likes
app.get('/api/articles/:id/likes', async (req, res) => {
    try {
        const userId = req.query.user_id;
        
        // ⭐⭐ CORRECCIÓN: Convertir string 'null' a NULL real
        let userIdParam = null;
        if (userId && userId !== 'null' && userId !== 'undefined') {
            userIdParam = parseInt(userId);
        }

        const result = await query(`
            SELECT COUNT(*) as like_count,
                   CASE 
                       WHEN $2::integer IS NULL THEN false
                       ELSE EXISTS(
                           SELECT 1 FROM article_likes 
                           WHERE article_id = $1 AND user_id = $2
                       )
                   END as user_liked
            FROM article_likes 
            WHERE article_id = $1
        `, [req.params.id, userIdParam]);

        res.json({
            success: true,
            likeCount: parseInt(result.rows[0].like_count),
            userLiked: result.rows[0].user_liked
        });
    } catch (err) {
        console.error('❌ Error obteniendo likes:', err);
        res.status(500).json({ error: "Error obteniendo likes" });
    }
});

// Dar like/quit like a un artículo
// En server.js - CORREGIR también la ruta POST de likes
app.post('/api/articles/:id/like', async (req, res) => {
    try {
        const { user_id, user_ip, user_agent } = req.body;
        const articleId = req.params.id;

        console.log('❤️ [LIKE] Solicitando like para artículo:', articleId, { user_id, user_ip });

        // ⭐⭐ CORRECCIÓN: Convertir user_id si es string 'null'
        let userIdParam = null;
        if (user_id && user_id !== 'null' && user_id !== 'undefined') {
            userIdParam = parseInt(user_id);
        }

        // Verificar que el artículo existe
        const articleCheck = await query('SELECT id FROM articles WHERE id = $1', [articleId]);
        if (articleCheck.rows.length === 0) {
            return res.status(404).json({ error: "Artículo no encontrado" });
        }

        // Verificar si ya dio like
        let likeCheckQuery = 'SELECT id FROM article_likes WHERE article_id = $1';
        let likeCheckParams = [articleId];

        if (userIdParam) {
            likeCheckQuery += ' AND user_id = $2';
            likeCheckParams.push(userIdParam);
        } else if (user_ip) {
            likeCheckQuery += ' AND user_ip = $2';
            likeCheckParams.push(user_ip);
        }

        const likeCheck = await query(likeCheckQuery, likeCheckParams);

        if (likeCheck.rows.length > 0) {
            // Quitar like (unlike)
            await query('DELETE FROM article_likes WHERE id = $1', [likeCheck.rows[0].id]);
            console.log('💔 [LIKE] Like removido');
            
            // Obtener nuevo conteo
            const newCount = await query('SELECT COUNT(*) FROM article_likes WHERE article_id = $1', [articleId]);
            
            res.json({
                success: true,
                liked: false,
                likeCount: parseInt(newCount.rows[0].count),
                message: "Like removido"
            });
        } else {
            // Dar like
            await query(`
                INSERT INTO article_likes (article_id, user_id, user_ip, user_agent) 
                VALUES ($1, $2, $3, $4)
            `, [articleId, userIdParam, user_ip || null, user_agent || null]);
            
            console.log('❤️ [LIKE] Like agregado');
            
            // Obtener nuevo conteo
            const newCount = await query('SELECT COUNT(*) FROM article_likes WHERE article_id = $1', [articleId]);
            
            res.json({
                success: true,
                liked: true,
                likeCount: parseInt(newCount.rows[0].count),
                message: "Like agregado"
            });
        }

    } catch (err) {
        console.error('❌ Error gestionando like:', err);
        res.status(500).json({ error: "Error gestionando like" });
    }
});
// Obtener artículos más populares (por likes)
app.get('/api/articles/popular', async (req, res) => {
    try {
        const result = await query(`
            SELECT a.*, u.name as author_name, COUNT(al.id) as like_count
            FROM articles a 
            LEFT JOIN users u ON a.author_id = u.id
            LEFT JOIN article_likes al ON a.id = al.article_id
            WHERE a.status = 'published'
            GROUP BY a.id, u.name
            ORDER BY like_count DESC, a.published_at DESC
            LIMIT 10
        `);

        res.json({
            success: true,
            articles: result.rows
        });
    } catch (err) {
        console.error('❌ Error obteniendo artículos populares:', err);
        res.status(500).json({ error: "Error obteniendo artículos populares" });
    }
});
// ==========================
// NOTIFICACIONES
// ==========================

// Obtener notificaciones del usuario
// ⭐⭐ DEBUG: Verificar notificaciones en la BD ⭐⭐
// En server.js - CORREGIR la ruta de notificaciones
app.get('/api/notifications', async (req, res) => {
    try {
        const userId = req.query.user_id;
        
        console.log('🔔 [NOTIFICATIONS] Solicitando notificaciones para usuario:', userId);
        
        if (!userId) {
            return res.status(400).json({ 
                success: false, 
                error: "user_id es requerido" 
            });
        }

        const result = await query(`
            SELECT * FROM notifications 
            WHERE user_id = $1 
            ORDER BY created_at DESC
            LIMIT 20
        `, [userId]);

        console.log('✅ [NOTIFICATIONS] Notificaciones encontradas:', result.rows.length);
        
        res.json({ 
            success: true, 
            notifications: result.rows 
        });
        
    } catch (err) {
        console.error('❌ Error obteniendo notificaciones:', err);
        res.status(500).json({ 
            success: false, 
            error: "Error obteniendo notificaciones: " + err.message 
        });
    }
});

// Crear notificación
app.post('/api/notifications', async (req, res) => {
    try {
        const { user_id, title, content, type, link } = req.body;

        if (!user_id || !title || !content) {
            return res.status(400).json({ error: "user_id, title y content son requeridos" });
        }

        const result = await query(`
            INSERT INTO notifications (user_id, title, content, type, link)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `, [user_id, title, content, type || 'info', link]);

        res.json({ success: true, notification: result.rows[0] });
    } catch (err) {
        console.error('❌ Error creando notificación:', err);
        res.status(500).json({ error: "Error creando notificación" });
    }
});

// Marcar notificación como leída
app.put('/api/notifications/:id/read', async (req, res) => {
    try {
        const result = await query(`
            UPDATE notifications SET read = true 
            WHERE id = $1 
            RETURNING *
        `, [req.params.id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Notificación no encontrada" });
        }

        res.json({ success: true, notification: result.rows[0] });
    } catch (err) {
        console.error('❌ Error actualizando notificación:', err);
        res.status(500).json({ error: "Error actualizando notificación" });
    }
});

// Eliminar notificación
app.delete('/api/notifications/:id', async (req, res) => {
    try {
        const result = await query(`
            DELETE FROM notifications 
            WHERE id = $1 
            RETURNING *
        `, [req.params.id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Notificación no encontrada" });
        }

        res.json({ success: true, message: "Notificación eliminada" });
    } catch (err) {
        console.error('❌ Error eliminando notificación:', err);
        res.status(500).json({ error: "Error eliminando notificación" });
    }
});

// ==========================
// ELIMINAR ARTÍCULO (SOLO ADMIN)
// ==========================
app.delete('/api/articles/:id', async (req, res) => {
    try {
        console.log('🗑️ [DELETE ARTICLE] Intentando eliminar artículo:', req.params.id);
        
        // Obtener el usuario que hace la solicitud desde el header
        const userRole = req.headers['user-role'];
        const userId = req.headers['user-id'];
        
        console.log('👤 [DELETE ARTICLE] Usuario solicitante:', { userId, userRole });
        
        // Verificar que solo administradores pueden eliminar
        if (userRole !== 'admin') {
            console.log('🚫 [DELETE ARTICLE] Usuario no autorizado para eliminar');
            return res.status(403).json({ 
                error: "No autorizado. Solo los administradores pueden eliminar artículos." 
            });
        }

        // Verificar que el artículo existe
        const articleCheck = await query(
            'SELECT id, title, author_id FROM articles WHERE id = $1',
            [req.params.id]
        );

        if (articleCheck.rows.length === 0) {
            console.log('❌ [DELETE ARTICLE] Artículo no encontrado');
            return res.status(404).json({ error: "Artículo no encontrado" });
        }

        const article = articleCheck.rows[0];
        console.log('📄 [DELETE ARTICLE] Artículo a eliminar:', article.title);

        // Eliminar comentarios relacionados primero (por las constraints de FK)
        console.log('🗑️ [DELETE ARTICLE] Eliminando comentarios relacionados...');
        await query('DELETE FROM comments WHERE article_id = $1', [req.params.id]);

        // Eliminar el artículo
        console.log('🗑️ [DELETE ARTICLE] Eliminando artículo de la base de datos...');
        const result = await query(
            'DELETE FROM articles WHERE id = $1 RETURNING *',
            [req.params.id]
        );

        console.log('✅ [DELETE ARTICLE] Artículo eliminado exitosamente');
        res.json({ 
            success: true, 
            message: "Artículo eliminado exitosamente",
            deletedArticle: result.rows[0]
        });

    } catch (err) {
        console.error('❌ [DELETE ARTICLE] Error eliminando artículo:', err.message);
        
        if (err.message.includes('foreign key constraint')) {
            return res.status(500).json({ 
                error: "No se puede eliminar el artículo porque tiene comentarios asociados" 
            });
        }
        
        res.status(500).json({ 
            error: "Error eliminando artículo: " + err.message 
        });
    }
});

// ==========================
// COMENTARIOS - CON LOGGING
// ==========================
app.post('/api/articles/:id/comments', async (req, res) => {
    try {
        const { author_id, content } = req.body;
        const result = await query(
            'INSERT INTO comments (article_id, author_id, content) VALUES ($1,$2,$3) RETURNING *',
            [req.params.id, author_id, content]
        );
        res.json({ success: true, comment: result.rows[0] });
    } catch (err) {
        console.error('❌ Error agregando comentario:', err);
        res.status(500).json({ error: "Error agregando comentario" });
    }
});
// ==========================
// ELIMINAR COMENTARIOS (SOLO ADMIN Y DOCENTE)
// ==========================
app.delete('/api/comments/:id', async (req, res) => {
    try {
        console.log('🗑️ [DELETE COMMENT] Intentando eliminar comentario:', req.params.id);
        
        // Obtener el usuario que hace la solicitud desde el header
        const userRole = req.headers['user-role'];
        const userId = req.headers['user-id'];
        
        console.log('👤 [DELETE COMMENT] Usuario solicitante:', { userId, userRole });
        
        // Verificar que solo administradores y docentes pueden eliminar comentarios
        if (userRole !== 'admin' && userRole !== 'teacher') {
            console.log('🚫 [DELETE COMMENT] Usuario no autorizado para eliminar comentarios');
            return res.status(403).json({ 
                error: "No autorizado. Solo administradores y docentes pueden eliminar comentarios." 
            });
        }

        // Verificar que el comentario existe
        const commentCheck = await query(
            `SELECT c.*, a.author_id as article_author_id 
             FROM comments c 
             JOIN articles a ON c.article_id = a.id 
             WHERE c.id = $1`,
            [req.params.id]
        );

        if (commentCheck.rows.length === 0) {
            console.log('❌ [DELETE COMMENT] Comentario no encontrado');
            return res.status(404).json({ error: "Comentario no encontrado" });
        }

        const comment = commentCheck.rows[0];
        console.log('💬 [DELETE COMMENT] Comentario a eliminar:', {
            id: comment.id,
            author: comment.author_id,
            content: comment.content.substring(0, 50) + '...'
        });

        // Eliminar el comentario
        console.log('🗑️ [DELETE COMMENT] Eliminando comentario de la base de datos...');
        const result = await query(
            'DELETE FROM comments WHERE id = $1 RETURNING *',
            [req.params.id]
        );

        console.log('✅ [DELETE COMMENT] Comentario eliminado exitosamente');
        res.json({ 
            success: true, 
            message: "Comentario eliminado exitosamente",
            deletedComment: result.rows[0]
        });

    } catch (err) {
        console.error('❌ [DELETE COMMENT] Error eliminando comentario:', err.message);
        res.status(500).json({ 
            error: "Error eliminando comentario: " + err.message 
        });
    }
});
// OBTENER COMENTARIOS DE UN ARTÍCULO
// ⭐⭐ VERIFICAR RUTA DE COMENTARIOS EN server.js ⭐⭐
app.get('/api/articles/:id/comments', async (req, res) => {
    try {
        console.log('💬 [API] Obteniendo comentarios para artículo:', req.params.id);
        
        const result = await query(`
            SELECT c.*, u.name as author_name 
            FROM comments c 
            LEFT JOIN users u ON c.author_id = u.id 
            WHERE c.article_id = $1 
            ORDER BY c.created_at DESC
        `, [req.params.id]);

        console.log('📊 [API] Comentarios encontrados en BD:', result.rows.length);
        res.json({ 
            success: true, 
            comments: result.rows 
        });

    } catch (err) {
        console.error('❌ Error obteniendo comentarios:', err);
        res.status(500).json({ 
            error: "Error obteniendo comentarios" 
        });
    }
});

// ==========================
// USUARIOS
// ==========================
app.get('/api/users', async (req, res) => {
    try {
        const result = await query(`
            SELECT id, username, name, role, talento, active, last_login
            FROM users ORDER BY id ASC
        `);
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error('❌ Error obteniendo usuarios:', err);
        res.status(500).json({ success: false, error: "Error obteniendo usuarios" });
    }
});

app.post('/api/users', async (req, res) => {
    try {
        const { username, password, name, role, talento } = req.body;
        const result = await query(`
            INSERT INTO users (username, password, name, role, talento)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, name, role, talento, active, last_login
        `, [username, password, name, role, talento]);
        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error('❌ Error creando usuario:', err);
        res.status(500).json({ success: false, error: "Error creando usuario" });
    }
});

app.put('/api/users/:id/status', async (req, res) => {
    try {
        const { active } = req.body;
        const result = await query(`
            UPDATE users SET active = $1 WHERE id = $2
            RETURNING id, username, name, role, talento, active, last_login
        `, [active, req.params.id]);
        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error('❌ Error actualizando estado:', err);
        res.status(500).json({ success: false, error: "Error actualizando estado del usuario" });
    }
});

// ==========================
// UTILIDADES
// ==========================
app.get('/api/debug-users', async (req, res) => {
    try {
        const result = await query('SELECT id, username, name, role, active FROM users ORDER BY id');
        res.json({ users: result.rows });
    } catch (error) {
        console.error('❌ Error obteniendo usuarios:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==========================
// PWA
// ==========================
app.get('/sw.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sw.js'));
});

app.get('/manifest.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});

// =============================================================================
// RUTA SPA - DEBE IR *ANTES* DE app.listen y AL FINAL DE LAS RUTAS
// =============================================================================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================================================
// INICIAR SERVIDOR - SIEMPRE AL FINAL
// =============================================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(60));
    console.log('🚀 REVISTA DIGITAL CSF - SERVIDOR EN EJECUCIÓN');
    console.log('📌 Puerto:', PORT);
    console.log('📌 Environment:', process.env.NODE_ENV);
    console.log('='.repeat(60));
});