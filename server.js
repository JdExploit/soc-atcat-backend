// server.js - Backend SOC especializado para ATCAT
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Conectar a MongoDB Atlas GRATIS
const MONGODB_URI = "mongodb+srv://username:password@cluster0.xxx.mongodb.net/soc-atcat?retryWrites=true&w=majority";
mongoose.connect(MONGODB_URI);

// Modelos para el SOC
const SecurityEvent = mongoose.model('SecurityEvent', {
    eventId: String,
    type: String, // 'login_attempt', 'sql_injection', 'xss', 'brute_force', etc.
    severity: String, // 'low', 'medium', 'high', 'critical'
    description: String,
    sourceIp: String,
    userAgent: String,
    targetUrl: String,
    payload: Object,
    timestamp: Date,
    blocked: Boolean
});

const UserActivity = mongoose.model('UserActivity', {
    userId: String,
    action: String,
    ip: String,
    userAgent: String,
    timestamp: Date,
    details: Object
});

const SystemMetric = mongoose.model('SystemMetric', {
    website: String,
    responseTime: Number,
    statusCode: Number,
    sslValid: Boolean,
    threatsBlocked: Number,
    timestamp: Date
});

// JWT Secret para autenticación
const JWT_SECRET = 'soc-atcat-secret-key-2024';

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// 🔍 ENDPOINTS PRINCIPALES DEL SOC

// Dashboard del SOC
app.get('/api/soc-dashboard', authenticateToken, async (req, res) => {
    try {
        const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
        
        const [
            totalEvents,
            criticalEvents,
            loginAttempts,
            blockedAttacks,
            recentEvents,
            systemMetrics
        ] = await Promise.all([
            SecurityEvent.countDocuments({ timestamp: { $gte: last24Hours } }),
            SecurityEvent.countDocuments({ 
                timestamp: { $gte: last24Hours },
                severity: { $in: ['high', 'critical'] }
            }),
            SecurityEvent.countDocuments({ 
                timestamp: { $gte: last24Hours },
                type: 'login_attempt'
            }),
            SecurityEvent.countDocuments({ 
                timestamp: { $gte: last24Hours },
                blocked: true
            }),
            SecurityEvent.find().sort({ timestamp: -1 }).limit(50),
            SystemMetric.find().sort({ timestamp: -1 }).limit(100)
        ]);

        res.json({
            summary: {
                totalEvents,
                criticalEvents,
                loginAttempts,
                blockedAttacks,
                successRate: totalEvents > 0 ? ((totalEvents - criticalEvents) / totalEvents * 100).toFixed(1) : 100
            },
            recentEvents,
            systemMetrics: systemMetrics.reverse(),
            charts: await generateSecurityCharts()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🔒 Endpoint para reportar eventos de seguridad DESDE ATCAT
app.post('/api/report-security-event', async (req, res) => {
    try {
        const {
            type,
            severity = 'medium',
            description,
            sourceIp,
            userAgent,
            targetUrl,
            payload = {},
            blocked = false
        } = req.body;

        const event = new SecurityEvent({
            eventId: 'SEC-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
            type,
            severity,
            description,
            sourceIp: sourceIp || req.ip,
            userAgent,
            targetUrl,
            payload,
            blocked,
            timestamp: new Date()
        });

        await event.save();

        // 🔔 Notificación en tiempo real (WebSocket)
        notifyRealTimeEvent(event);

        res.json({ success: true, eventId: event.eventId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🌐 Monitoreo automático de ATCAT
app.post('/api/monitor-atcat', async (req, res) => {
    const targetUrl = 'https://atcat.netlify.app'; // Tu URL de ATCAT
    
    try {
        const securityScan = await performComprehensiveSecurityScan(targetUrl);
        
        // Guardar métricas
        const metric = new SystemMetric({
            website: targetUrl,
            responseTime: securityScan.responseTime,
            statusCode: securityScan.statusCode,
            sslValid: securityScan.sslValid,
            threatsBlocked: securityScan.threatsDetected,
            timestamp: new Date()
        });
        await metric.save();

        // Crear eventos para amenazas detectadas
        for (const threat of securityScan.threats) {
            const event = new SecurityEvent({
                eventId: 'SCAN-' + Date.now(),
                type: 'security_scan',
                severity: threat.severity,
                description: threat.description,
                sourceIp: 'scanner',
                userAgent: 'SOC-Scanner',
                targetUrl: targetUrl,
                payload: threat,
                blocked: false,
                timestamp: new Date()
            });
            await event.save();
        }

        res.json(securityScan);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 📊 Estadísticas detalladas
app.get('/api/security-stats', authenticateToken, async (req, res) => {
    try {
        const last7Days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        
        const stats = await SecurityEvent.aggregate([
            { $match: { timestamp: { $gte: last7Days } } },
            {
                $group: {
                    _id: {
                        type: '$type',
                        day: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
                    },
                    count: { $sum: 1 },
                    blocked: { $sum: { $cond: ['$blocked', 1, 0] } }
                }
            }
        ]);

        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🔍 Búsqueda de eventos
app.get('/api/search-events', authenticateToken, async (req, res) => {
    try {
        const { query, type, severity, dateFrom, dateTo } = req.query;
        let filter = {};

        if (query) {
            filter.$or = [
                { description: { $regex: query, $options: 'i' } },
                { sourceIp: { $regex: query, $options: 'i' } },
                { eventId: { $regex: query, $options: 'i' } }
            ];
        }

        if (type) filter.type = type;
        if (severity) filter.severity = severity;
        if (dateFrom || dateTo) {
            filter.timestamp = {};
            if (dateFrom) filter.timestamp.$gte = new Date(dateFrom);
            if (dateTo) filter.timestamp.$lte = new Date(dateTo);
        }

        const events = await SecurityEvent.find(filter).sort({ timestamp: -1 }).limit(100);
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 🛡️ Funciones de escaneo de seguridad
async function performComprehensiveSecurityScan(url) {
    const startTime = Date.now();
    
    try {
        const response = await axios.get(url, { 
            timeout: 10000,
            headers: {
                'User-Agent': 'SOC-Security-Scanner/1.0'
            }
        });
        
        const responseTime = Date.now() - startTime;
        
        // Análisis de seguridad
        const securityAnalysis = await analyzeSecurity(response, url);
        
        return {
            url,
            statusCode: response.status,
            responseTime,
            sslValid: url.startsWith('https://'),
            threatsDetected: securityAnalysis.threats.length,
            threats: securityAnalysis.threats,
            headers: securityAnalysis.headers,
            timestamp: new Date()
        };
    } catch (error) {
        return {
            url,
            statusCode: error.response?.status || 0,
            responseTime: Date.now() - startTime,
            sslValid: false,
            threatsDetected: 1,
            threats: [{
                type: 'availability',
                severity: 'critical',
                description: `Sitio no disponible: ${error.message}`
            }],
            timestamp: new Date()
        };
    }
}

async function analyzeSecurity(response, url) {
    const threats = [];
    const headers = response.headers;

    // Verificar headers de seguridad
    if (!headers['x-frame-options']) {
        threats.push({
            type: 'security_header',
            severity: 'medium',
            description: 'Falta header X-Frame-Options (clickjacking protection)'
        });
    }

    if (!headers['x-content-type-options']) {
        threats.push({
            type: 'security_header', 
            severity: 'low',
            description: 'Falta header X-Content-Type-Options'
        });
    }

    // Analizar contenido en busca de vulnerabilidades
    const content = response.data;
    
    // Detectar posibles exposición de información sensible
    if (content.includes('password') || content.includes('secret') || content.includes('api_key')) {
        threats.push({
            type: 'information_disclosure',
            severity: 'high', 
            description: 'Posible exposición de información sensible en el contenido'
        });
    }

    // Verificar mixed content
    if (content.includes('http://') && url.startsWith('https://')) {
        threats.push({
            type: 'mixed_content',
            severity: 'medium',
            description: 'Contenido mixto (HTTP en HTTPS) detectado'
        });
    }

    return { threats, headers };
}

// 📈 Generar datos para gráficos
async function generateSecurityCharts() {
    const last7Days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    const eventsByType = await SecurityEvent.aggregate([
        { $match: { timestamp: { $gte: last7Days } } },
        { $group: { _id: '$type', count: { $sum: 1 } } }
    ]);

    const eventsBySeverity = await SecurityEvent.aggregate([
        { $match: { timestamp: { $gte: last7Days } } },
        { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]);

    const dailyEvents = await SecurityEvent.aggregate([
        { $match: { timestamp: { $gte: last7Days } } },
        {
            $group: {
                _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
                count: { $sum: 1 }
            }
        },
        { $sort: { _id: 1 } }
    ]);

    return {
        byType: eventsByType,
        bySeverity: eventsBySeverity, 
        daily: dailyEvents
    };
}

// 🔔 Notificaciones en tiempo real (WebSocket simple)
function notifyRealTimeEvent(event) {
    // En una implementación real, aquí iría la lógica de WebSockets
    console.log('🔔 NUEVO EVENTO DE SEGURIDAD:', {
        id: event.eventId,
        type: event.type,
        severity: event.severity,
        description: event.description
    });
}

// ⏰ Monitoreo automático cada 5 minutos
setInterval(async () => {
    try {
        await performComprehensiveSecurityScan('https://atcat.netlify.app');
        console.log('✅ Monitoreo automático completado:', new Date().toISOString());
    } catch (error) {
        console.error('❌ Error en monitoreo automático:', error.message);
    }
}, 5 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 SOC ATCAT funcionando en puerto ${PORT}`);
    console.log(`🌐 Monitoreando: https://atcat.netlify.app`);
});
