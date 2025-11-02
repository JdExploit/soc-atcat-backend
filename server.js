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
  timestamp: { type: Date, default: Date.now },
  blocked: Boolean
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
    cluster: 'jdexploit'
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
      blocked: false
    });
    await testEvent.save();

    res.json({
      status: 'success',
      message: '✅ SOC ATCAT funcionando correctamente',
      database: 'Conectado a MongoDB Atlas',
      testEventId: testEvent.eventId
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/soc-dashboard', async (req, res) => {
  try {
    const [events, metrics, totalEvents, criticalEvents] = await Promise.all([
      SecurityEvent.find().sort({ timestamp: -1 }).limit(20),
      SystemMetric.find().sort({ timestamp: -1 }).limit(10),
      SecurityEvent.countDocuments(),
      SecurityEvent.countDocuments({ severity: { $in: ['high', 'critical'] } })
    ]);

    res.json({
      summary: {
        totalEvents,
        criticalEvents,
        successRate: '98.5%'
      },
      recentEvents: events,
      systemMetrics: metrics
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/monitor-atcat', async (req, res) => {
  try {
    const start = Date.now();
    const response = await axios.get('https://atcat.netlify.app', { timeout: 10000 });
    const responseTime = Date.now() - start;

    const metric = new SystemMetric({
      website: 'https://atcat.netlify.app',
      responseTime,
      statusCode: response.status,
      sslValid: true
    });
    await metric.save();

    res.json({
      success: true,
      responseTime: responseTime + 'ms',
      status: 'online',
      message: '✅ ATCAT está online y funcionando'
    });
  } catch (error) {
    const alert = new SecurityEvent({
      eventId: 'ALERT-' + Date.now(),
      type: 'availability',
      severity: 'critical',
      description: `ATCAT no accesible: ${error.message}`,
      sourceIp: 'soc-monitor',
      blocked: false
    });
    await alert.save();

    res.status(500).json({
      success: false,
      error: 'ATCAT no disponible',
      alertCreated: true
    });
  }
});

app.post('/api/simulate-events', async (req, res) => {
  const events = [
    {
      type: 'login_attempt',
      severity: 'medium',
      description: 'Intento de login fallido desde IP 192.168.1.100',
      sourceIp: '192.168.1.100',
      blocked: true
    },
    {
      type: 'sql_injection', 
      severity: 'high',
      description: 'Intento de SQL injection detectado',
      sourceIp: '203.0.113.45',
      blocked: true
    },
    {
      type: 'xss_attempt',
      severity: 'high',
      description: 'Intento de XSS detectado en formulario',
      sourceIp: '198.51.100.23',
      blocked: true
    }
  ];

  try {
    for (const eventData of events) {
      const event = new SecurityEvent({
        eventId: 'SIM-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
        ...eventData
      });
      await event.save();
    }

    res.json({ 
      success: true, 
      message: '🧪 Eventos de prueba creados exitosamente',
      eventsCreated: events.length 
    });
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
});
