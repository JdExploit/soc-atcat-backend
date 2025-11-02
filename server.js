const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// 🔗 TU CADENA DE CONEXIÓN COMPLETA
const MONGODB_URI = "mongodb+srv://soc_atcat_user:SocAtcat2025!Secure@jdexploit.fufjeqm.mongodb.net/soc-atcat?retryWrites=true&w=majority&appName=jdexploit";

console.log('🚀 Iniciando SOC ATCAT Backend...');

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Conectado exitosamente a MongoDB Atlas!');
    console.log('📊 Cluster: jdexploit.fufjeqm.mongodb.net');
    console.log('🌍 Región: Paris (eu-west-3)');
    console.log('👤 Usuario: soc_atcat_user');
  })
  .catch(err => {
    console.log('❌ Error conectando a MongoDB:', err.message);
  });

// Modelos
const SecurityEvent = mongoose.model('SecurityEvent', {
  eventId: String,
  type: String,
  severity: String,
  description: String,
  sourceIp: String,
  userAgent: String,
  targetUrl: String,
  payload: Object,
  timestamp: { type: Date, default: Date.now },
  blocked: Boolean,
  attackVector: String
});

const SystemMetric = mongoose.model('SystemMetric', {
  website: String,
  responseTime: Number,
  statusCode: Number,
  sslValid: Boolean,
  timestamp: { type: Date, default: Date.now }
});

// Endpoints
app.get('/', (req, res) => {
  res.json({
    message: '🛡️ SOC ATCAT - Security Operations Center',
    status: 'Operativo',
    database: mongoose.connection.readyState === 1 ? '✅ Conectado' : '❌ Desconectado',
    cluster: 'jdexploit',
    version: '3.0 - Con ataques realistas'
  });
});

app.get('/api/test', async (req, res) => {
  try {
    const testEvent = new SecurityEvent({
      eventId: 'TEST-' + Date.now(),
      type: 'connection_test',
      severity: 'low',
      description: 'Prueba de conexión exitosa del SOC ATCAT',
      sourceIp: req.ip,
      userAgent: req.get('User-Agent'),
      blocked: false,
      attackVector: 'System Check'
    });
    await testEvent.save();

    res.json({
      status: 'success',
      message: '✅ SOC ATCAT funcionando correctamente',
      database: 'Conectado a MongoDB Atlas',
      testEventId: testEvent.eventId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/soc-dashboard', async (req, res) => {
  try {
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const [events, metrics, totalEvents, criticalEvents, loginAttempts, blockedEvents] = await Promise.all([
      SecurityEvent.find().sort({ timestamp: -1 }).limit(25),
      SystemMetric.find().sort({ timestamp: -1 }).limit(15),
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
      })
    ]);

    res.json({
      summary: {
        totalEvents,
        criticalEvents,
        loginAttempts,
        blockedEvents,
        successRate: totalEvents > 0 ? ((blockedEvents / totalEvents) * 100).toFixed(1) + '%' : '100%'
      },
      recentEvents: events,
      systemMetrics: metrics,
      systemInfo: {
        database: 'MongoDB Atlas',
        cluster: 'jdexploit',
        region: 'Paris (eu-west-3)',
        status: 'operational'
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/monitor-atcat', async (req, res) => {
  const targetUrl = 'https://atcat.netlify.app';
  
  try {
    console.log('🔍 Monitoreando ATCAT...');
    const startTime = Date.now();
    
    const response = await axios.get(targetUrl, { 
      timeout: 15000,
      headers: {
        'User-Agent': 'SOC-ATCAT-Monitor/1.0'
      }
    });
    
    const responseTime = Date.now() - startTime;

    // Guardar métrica
    const metric = new SystemMetric({
      website: targetUrl,
      responseTime: responseTime,
      statusCode: response.status,
      sslValid: true,
    });
    await metric.save();

    console.log('✅ ATCAT monitorizado correctamente');

    res.json({
      success: true,
      website: targetUrl,
      responseTime: responseTime + 'ms',
      statusCode: response.status,
      sslValid: true,
      message: '✅ ATCAT está online y funcionando',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.log('❌ Error monitoreando ATCAT:', error.message);

    // Crear alerta de seguridad
    const alert = new SecurityEvent({
      eventId: 'ALERT-' + Date.now(),
      type: 'availability',
      severity: 'critical',
      description: `ATCAT no accesible: ${error.message}`,
      sourceIp: 'soc-monitoring-system',
      userAgent: 'SOC-Monitor',
      targetUrl: targetUrl,
      blocked: false,
      payload: {
        error: error.message,
        code: error.code
      },
      attackVector: 'Availability Attack'
    });
    await alert.save();

    res.status(500).json({
      success: false,
      error: error.message,
      alertCreated: true,
      alertId: alert.eventId,
      message: '❌ ATCAT no está disponible'
    });
  }
});

// 🧪 SIMULACIÓN BÁSICA (original)
app.post('/api/simulate-events', async (req, res) => {
  const events = [
    {
      type: 'login_attempt',
      severity: 'medium',
      description: 'Intento de login fallido desde IP 192.168.1.100',
      sourceIp: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      targetUrl: 'https://atcat.netlify.app/login',
      blocked: true,
      attackVector: 'Credential Attack'
    },
    {
      type: 'sql_injection', 
      severity: 'high',
      description: 'Intento de SQL injection detectado',
      sourceIp: '203.0.113.45',
      userAgent: 'Python-urllib/3.9',
      targetUrl: 'https://atcat.netlify.app/api/users',
      blocked: true,
      attackVector: 'Database Injection'
    },
    {
      type: 'xss_attempt',
      severity: 'high',
      description: 'Intento de XSS detectado en formulario',
      sourceIp: '198.51.100.23',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      targetUrl: 'https://atcat.netlify.app/contact',
      blocked: true,
      attackVector: 'Client-Side Injection'
    }
  ];

  try {
    const createdEvents = [];
    
    for (const eventData of events) {
      const event = new SecurityEvent({
        eventId: 'SIM-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
        ...eventData
      });
      await event.save();
      createdEvents.push(event.eventId);
    }

    res.json({ 
      success: true, 
      message: '🧪 Eventos de prueba creados exitosamente',
      eventsCreated: events.length,
      eventIds: createdEvents
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🔥 TESTS DE ATAQUE REALISTAS
app.post('/api/simulate-real-attacks', async (req, res) => {
  const realAttacks = [
    // 1. ATAQUE DE FUERZA BRUTA
    {
      type: 'brute_force_attack',
      severity: 'high',
      description: 'Ataque de fuerza bruta detectado - Múltiples intentos de login fallidos',
      sourceIp: '185.143.223.15', // IP real de Rusia
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
      targetUrl: 'https://atcat.netlify.app/login',
      payload: {
        username: 'admin',
        attempts: 47,
        timeFrame: '5 minutes',
        success: false
      },
      blocked: true,
      attackVector: 'Credential Stuffing'
    },
    
    // 2. SQL INJECTION AVANZADO
    {
      type: 'sql_injection',
      severity: 'critical',
      description: 'SQL Injection avanzado detectado en endpoint /api/users',
      sourceIp: '203.0.113.45', // IP de testing
      userAgent: 'sqlmap/1.6#stable (https://sqlmap.org)',
      targetUrl: 'https://atcat.netlify.app/api/users',
      payload: {
        injectionType: 'Union-based',
        payload: "' UNION SELECT 1,2,3,@@version-- -",
        databaseType: 'MySQL',
        parameters: ['id', 'search']
      },
      blocked: true,
      attackVector: 'Database Injection'
    },
    
    // 3. XSS PERSISTENTE
    {
      type: 'xss_attack',
      severity: 'high',
      description: 'Cross-site scripting (XSS) persistente detectado en formulario de comentarios',
      sourceIp: '198.51.100.23',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      targetUrl: 'https://atcat.netlify.app/contact',
      payload: {
        vector: 'Persistent XSS',
        payload: '<script>alert("XSS")</script>',
        location: 'comment_field',
        sanitized: true
      },
      blocked: true,
      attackVector: 'Client-Side Injection'
    },
    
    // 4. SCAN DE VULNERABILIDADES
    {
      type: 'vulnerability_scan',
      severity: 'medium',
      description: 'Scan automatizado de vulnerabilidades detectado',
      sourceIp: '192.0.2.128',
      userAgent: 'Mozilla/5.0 (compatible; Nessus/10.0.0)',
      targetUrl: 'https://atcat.netlify.app',
      payload: {
        scanner: 'Nessus',
        testsPerformed: 1247,
        vulnerabilitiesFound: 3,
        scanDuration: '2h 15m'
      },
      blocked: false,
      attackVector: 'Reconnaissance'
    },
    
    // 5. ATAQUE DDoS
    {
      type: 'ddos_attack',
      severity: 'critical',
      description: 'Posible ataque DDoS - Tráfico anómalo desde múltiples IPs',
      sourceIp: 'BOTNET (Multiple IPs)',
      userAgent: 'Various',
      targetUrl: 'https://atcat.netlify.app',
      payload: {
        requestsPerSecond: 2450,
        duration: '8 minutes',
        sourceCountries: ['China', 'Russia', 'Brazil', 'Vietnam'],
        attackType: 'HTTP Flood'
      },
      blocked: true,
      attackVector: 'Volumetric Attack'
    },
    
    // 6. PHISHING ATTEMPT
    {
      type: 'phishing_attempt',
      severity: 'high',
      description: 'Intento de phishing detectado - Formulario fake de login',
      sourceIp: '203.0.113.67',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      targetUrl: 'https://atcat-clone-fake.com/login', // Dominio fake
      payload: {
        fakeDomain: 'atcat-clone-fake.com',
        targetCredentials: ['username', 'password'],
        technique: 'Clone Site'
      },
      blocked: true,
      attackVector: 'Social Engineering'
    },
    
    // 7. DATA LEAKAGE
    {
      type: 'data_leakage',
      severity: 'critical',
      description: 'Posible fuga de datos - Acceso a archivos sensibles',
      sourceIp: '198.51.100.89',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
      targetUrl: 'https://atcat.netlify.app/.env',
      payload: {
        fileAccessed: '.env',
        contains: 'API keys, Database credentials',
        exposed: true
      },
      blocked: true,
      attackVector: 'Information Disclosure'
    },
    
    // 8. COMMAND INJECTION
    {
      type: 'command_injection',
      severity: 'critical',
      description: 'Intento de inyección de comandos en panel administrativo',
      sourceIp: '203.0.113.12',
      userAgent: 'curl/7.68.0',
      targetUrl: 'https://atcat.netlify.app/admin/system',
      payload: {
        command: '; cat /etc/passwd',
        parameters: ['system_command'],
        os: 'Linux'
      },
      blocked: true,
      attackVector: 'OS Command Injection'
    }
  ];

  try {
    const createdEvents = [];
    
    for (const attackData of realAttacks) {
      const event = new SecurityEvent({
        eventId: 'ATTACK-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6),
        ...attackData
      });
      
      await event.save();
      createdEvents.push(event.eventId);
      
      // Pequeño delay para simular tiempo real
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    res.json({ 
      success: true, 
      message: '🔥 SIMULACIÓN DE ATAQUES REALISTAS COMPLETADA',
      attacksExecuted: realAttacks.length,
      eventsCreated: createdEvents.length,
      attackTypes: [...new Set(realAttacks.map(a => a.type))]
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🎯 SIMULACIÓN DE ATAQUE ESPECÍFICO
app.post('/api/simulate-specific-attack', async (req, res) => {
  const { attackType } = req.body;
  
  const attackLibrary = {
    sql_injection: {
      type: 'sql_injection',
      severity: 'critical',
      description: 'SQL Injection detectado en parámetro user_id',
      sourceIp: '203.0.113.' + Math.floor(Math.random() * 255),
      userAgent: 'sqlmap/1.6#stable',
      targetUrl: 'https://atcat.netlify.app/api/users',
      payload: {
        injectionType: 'Boolean-based',
        payload: "' OR '1'='1' -- -",
        parameter: 'user_id'
      },
      blocked: true,
      attackVector: 'Database Injection'
    },
    
    xss_attack: {
      type: 'xss_attack',
      severity: 'high',
      description: 'XSS reflejado detectado en búsqueda',
      sourceIp: '198.51.100.' + Math.floor(Math.random() * 255),
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      targetUrl: 'https://atcat.netlify.app/search',
      payload: {
        vector: 'Reflected XSS',
        payload: '<img src=x onerror=alert(1)>',
        parameter: 'q'
      },
      blocked: true,
      attackVector: 'Client-Side Injection'
    },
    
    brute_force: {
      type: 'brute_force_attack',
      severity: 'high',
      description: 'Ataque de diccionario en endpoint de login',
      sourceIp: '192.0.2.' + Math.floor(Math.random() * 255),
      userAgent: 'Hydra/9.3 (https://github.com/vanhauser-thc/thc-hydra)',
      targetUrl: 'https://atcat.netlify.app/login',
      payload: {
        attempts: 156,
        wordlist: 'rockyou.txt',
        usernames: ['admin', 'root', 'test']
      },
      blocked: true,
      attackVector: 'Credential Attack'
    },
    
    port_scan: {
      type: 'port_scanning',
      severity: 'medium',
      description: 'Scan de puertos detectado desde red externa',
      sourceIp: '203.0.113.' + Math.floor(Math.random() * 255),
      userAgent: 'nmap/7.80',
      targetUrl: 'https://atcat.netlify.app',
      payload: {
        portsScanned: 1024,
        technique: 'SYN Scan',
        duration: '45 seconds'
      },
      blocked: false,
      attackVector: 'Network Reconnaissance'
    },
    
    ddos_attack: {
      type: 'ddos_attack',
      severity: 'critical',
      description: 'Ataque DDoS distribuido desde múltiples ubicaciones',
      sourceIp: 'MULTIPLE_IPS',
      userAgent: 'Various Botnets',
      targetUrl: 'https://atcat.netlify.app',
      payload: {
        requestsPerSecond: 3200,
        attackType: 'HTTP Flood',
        duration: '12 minutes',
        sourceCount: 1450
      },
      blocked: true,
      attackVector: 'Volumetric Attack'
    }
  };

  if (!attackLibrary[attackType]) {
    return res.status(400).json({ error: 'Tipo de ataque no válido' });
  }

  try {
    const event = new SecurityEvent({
      eventId: 'ATK-' + Date.now() + '-' + attackType.toUpperCase(),
      ...attackLibrary[attackType]
    });

    await event.save();

    res.json({
      success: true,
      message: `🎯 ATAQUE ${attackType.toUpperCase()} SIMULADO`,
      eventId: event.eventId,
      attackDetails: attackLibrary[attackType]
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 📊 ESTADÍSTICAS AVANZADAS
app.get('/api/security-stats', async (req, res) => {
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

    const attackTypes = await SecurityEvent.aggregate([
      { $match: { timestamp: { $gte: last7Days } } },
      { $group: { _id: '$type', count: { $sum: 1 } } }
    ]);

    res.json({
      dailyStats: stats,
      attackTypes: attackTypes,
      totalPeriodEvents: await SecurityEvent.countDocuments({ timestamp: { $gte: last7Days } })
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🔍 BÚSQUEDA DE EVENTOS
app.get('/api/search-events', async (req, res) => {
  try {
    const { query, type, severity, dateFrom, dateTo } = req.query;
    let filter = {};

    if (query) {
      filter.$or = [
        { description: { $regex: query, $options: 'i' } },
        { sourceIp: { $regex: query, $options: 'i' } },
        { eventId: { $regex: query, $options: 'i' } },
        { attackVector: { $regex: query, $options: 'i' } }
      ];
    }

    if (type) filter.type = type;
    if (severity) filter.severity = severity;
    if (dateFrom || dateTo) {
      filter.timestamp = {};
      if (dateFrom) filter.timestamp.$gte = new Date(dateFrom);
      if (dateTo) filter.timestamp.$lte = new Date(dateTo);
    }

    const events = await SecurityEvent.find(filter).sort({ timestamp: -1 }).limit(50);
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 SOC Backend ejecutándose en puerto ${PORT}`);
  console.log(`📍 URLs disponibles:`);
  console.log(`   → http://localhost:${PORT}/api/test`);
  console.log(`   → http://localhost:${PORT}/api/soc-dashboard`);
  console.log(`   → http://localhost:${PORT}/api/security-stats`);
  console.log(`   → http://localhost:${PORT}/api/search-events`);
  console.log(`🔥 Endpoints de ataque:`);
  console.log(`   → POST /api/simulate-real-attacks`);
  console.log(`   → POST /api/simulate-specific-attack`);
  console.log(`🌐 Monitoreando: https://atcat.netlify.app`);
});
