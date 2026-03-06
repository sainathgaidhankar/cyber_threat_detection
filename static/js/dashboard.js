/* ============================================
   Dashboard JavaScript - Enhanced UX
   Cyber Threat Detection System
   ============================================ */

let attackChart = null;
let updateInterval = null;

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load metrics every 3 seconds
    updateInterval = setInterval(updateMetrics, 3000);
    
    // Initial load
    updateMetrics();
    
    // Add keyboard shortcut support
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'Enter') {
            document.getElementById('analyzeBtn')?.click();
        }
    });
});

/**
 * Smoothly update stat values with visual feedback
 */
function updateStatValue(elementId, newValue) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const currentValue = element.textContent;
    if (currentValue !== String(newValue)) {
        element.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        element.style.opacity = '0.6';
        element.style.transform = 'scale(0.95)';
        
        setTimeout(() => {
            element.textContent = newValue;
            element.style.opacity = '1';
            element.style.transform = 'scale(1)';
        }, 150);
    }
}

/**
 * Update all metrics and statistics with smooth transitions
 */
function updateMetrics() {
    fetch('/api/metrics')
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                console.error('Metrics error:', data.error);
                return;
            }
            
            // Update stat cards with smooth animation
            updateStatValue('totalPredictions', data.total_predictions || 0);
            
            const avgConf = data.average_confidence ? (data.average_confidence * 100).toFixed(1) : 0;
            updateStatValue('avgConfidence', avgConf + '%');
            
            // Count threats vs safe
            let threats = 0, safe = 0;
            const distribution = data.attack_distribution || {};
            for (const [attack, count] of Object.entries(distribution)) {
                if (attack.toLowerCase() === 'normal') {
                    safe += count;
                } else {
                    threats += count;
                }
            }
            
            updateStatValue('threatsDetected', threats);
            updateStatValue('safeFlows', safe);
            
            // Update chart
            updateChart(distribution);
            
            // Update predictions list
            updatePredictionsList(data.latest_predictions || []);
        })
        .catch(e => {
            console.error('Fetch error:', e);
            showNotification('Failed to load metrics', 'error');
        });
}

/**
 * Update attack distribution chart with smooth transitions
 */
function updateChart(distribution) {
    const labels = Object.keys(distribution);
    const values = Object.values(distribution);
    
    // Color palette for chart
    const colors = [
        '#6366f1', '#a855f7', '#ec4899', '#f43f5e',
        '#f97316', '#eab308', '#84cc16', '#22c55e',
        '#10b981', '#14b8a6', '#06b6d4', '#0ea5e9',
        '#3b82f6', '#8b5cf6', '#d946ef', '#e11d48'
    ];
    
    if (!attackChart && labels.length > 0) {
        const ctx = document.getElementById('attackChart');
        if (!ctx) return;
        
        attackChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors.slice(0, labels.length),
                    borderColor: '#1e293b',
                    borderWidth: 3,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 750,
                    easing: 'easeInOutQuart'
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#cbd5e1',
                            font: {
                                size: 12,
                                family: "'Inter', sans-serif"
                            },
                            padding: 15,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(30, 41, 59, 0.95)',
                        titleColor: '#e2e8f0',
                        bodyColor: '#cbd5e1',
                        borderColor: '#4f46e5',
                        borderWidth: 1,
                        padding: 12,
                        titleFont: { size: 13, weight: 'bold' },
                        bodyFont: { size: 12 },
                        callbacks: {
                            label: function(context) {
                                return context.label + ': ' + context.parsed.y + ' flows';
                            }
                        }
                    }
                }
            }
        });
    } else if (attackChart && labels.length > 0) {
        attackChart.data.labels = labels;
        attackChart.data.datasets[0].data = values;
        attackChart.data.datasets[0].backgroundColor = colors.slice(0, labels.length);
        attackChart.update('active');
    }
}

/**
 * Update the predictions list with smooth transitions
 */
function updatePredictionsList(predictions) {
    const list = document.getElementById('predictionsList');
    if (!list) return;
    
    if (predictions.length === 0) {
        list.innerHTML = `<div class="flex items-center justify-center py-8">
            <p class="text-muted">No predictions yet. Analyze a network flow to get started.</p>
        </div>`;
        return;
    }
    
    list.innerHTML = predictions.reverse().slice(0, 10).map((p, idx) => {
        const conf = (p.confidence * 100).toFixed(1);
        const time = new Date(p.timestamp).toLocaleTimeString();
        
        // Determine threat indicator emoji
        let indicator = '';
        if (p.prediction.toLowerCase() === 'normal') {
            indicator = '✓';
        } else if (conf > 80) {
            indicator = '🚨';
        } else {
            indicator = '⚠️';
        }
        
        return `<div class="prediction-item" style="animation: slideInUp 0.3s ease-out; animation-delay: ${idx * 0.05}s;">
            <div class="flex items-start justify-between">
                <div class="flex-1">
                    <div class="flex items-center gap-2">
                        <span class="text-lg">${indicator}</span>
                        <strong class="text-indigo-300">${p.prediction}</strong>
                        <span class="text-indigo-400 ml-auto">${conf}%</span>
                    </div>
                </div>
            </div>
            <small class="text-gray-500 block mt-1">⏰ ${time}</small>
        </div>`;
    }).join('');
}

/**
 * Load a sample data file with visual feedback
 */
function loadSample(filename) {
    const csvInput = document.getElementById('csvInput');
    if (!csvInput) return;
    
    // Visual feedback
    csvInput.style.opacity = '0.7';
    csvInput.style.animation = 'pulse 1s';
    
    fetch(`/api/samples`)
        .then(r => r.json())
        .then(data => {
            const sample = data.samples.find(s => s.filename === filename);
            if (sample && sample.sample_data) {
                csvInput.value = sample.sample_data.join(',');
                csvInput.focus();
                
                // Flash animation
                csvInput.style.opacity = '1';
                csvInput.style.borderColor = '#a855f7';
                setTimeout(() => {
                    csvInput.style.borderColor = '';
                }, 300);
                
                showNotification(`✓ ${filename.replace('_', ' ').replace('.csv', '')} loaded`, 'success');
            }
        })
        .catch(e => {
            console.error('Failed to load sample:', e);
            showNotification('Failed to load sample data', 'error');
            csvInput.style.opacity = '1';
        });
}

/**
 * Submit CSV row for analysis with enhanced UX
 */
function submitCSV() {
    const csvInput = document.getElementById('csvInput');
    const csv = csvInput.value.trim();
    
    if (!csv) {
        showNotification('Please enter or load a CSV row', 'warning');
        csvInput.focus();
        csvInput.style.borderColor = '#ef4444';
        setTimeout(() => {
            csvInput.style.borderColor = '';
        }, 500);
        return;
    }
    
    const loading = document.getElementById('loading');
    const resultBox = document.getElementById('resultBox');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    // Show loading state
    loading.classList.remove('hidden');
    resultBox.classList.add('hidden');
    analyzeBtn.disabled = true;
    analyzeBtn.style.opacity = '0.6';
    
    fetch('/api/submit-row', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ row: csv })
    })
    .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
    })
    .then(data => {
        loading.classList.add('hidden');
        
        if (data.error) {
            showNotification('Error: ' + data.error, 'error');
            analyzeBtn.disabled = false;
            analyzeBtn.style.opacity = '1';
            return;
        }
        
        const result = data.result || {};
        const pred = result.prediction || 'Unknown';
        const conf = result.confidence ? (result.confidence * 100).toFixed(1) : 0;
        
        // Determine threat class and icon
        let threatClass = 'threat-safe';
        let threatIcon = '✓';
        let threatText = 'SAFE';
        
        if (pred.toLowerCase() === 'normal') {
            threatClass = 'threat-safe';
            threatIcon = '✓';
            threatText = 'SAFE';
        } else {
            threatText = 'THREAT DETECTED';
            threatIcon = conf > 80 ? '🚨' : '⚠️';
            threatClass = conf > 80 ? 'threat-critical' : 'threat-warning';
        }
        
        const html = `<div class="${threatClass}">
            <div class="flex items-center gap-3 mb-3">
                <span class="text-3xl sm:text-4xl">${threatIcon}</span>
                <div class="flex-1">
                    <div class="threat-type">${pred.toUpperCase()}</div>
                    <div class="text-xs text-gray-400">${threatText}</div>
                </div>
            </div>
            <div class="threat-confidence flex items-center justify-between">
                <span>Confidence Score</span>
                <span class="font-bold text-lg">${conf}%</span>
            </div>
            <div class="mt-3 pt-3 border-t border-current opacity-50 text-xs">
                Analysis completed successfully • MachineLearning Model: RandomForest
            </div>
        </div>`;
        
        document.getElementById('threatResult').innerHTML = html;
        resultBox.classList.remove('hidden');
        
        // Re-enable button
        analyzeBtn.disabled = false;
        analyzeBtn.style.opacity = '1';
        
        // Refresh metrics after prediction
        setTimeout(updateMetrics, 500);
        
        showNotification('✓ Analysis complete', 'success');
    })
    .catch(e => {
        loading.classList.add('hidden');
        analyzeBtn.disabled = false;
        analyzeBtn.style.opacity = '1';
        
        console.error('Submission error:', e);
        showNotification('Failed to analyze: ' + e.message, 'error');
    });
}

/**
 * Show notification toast messages
 */
function showNotification(message, type = 'info') {
    // Prevent multiple notifications
    const existing = document.getElementById('notification');
    if (existing) existing.remove();
    
    const notification = document.createElement('div');
    notification.id = 'notification';
    
    const bgColor = {
        'success': 'bg-green-500/20 border-green-500',
        'error': 'bg-red-500/20 border-red-500',
        'warning': 'bg-amber-500/20 border-amber-500',
        'info': 'bg-blue-500/20 border-blue-500'
    }[type] || 'bg-blue-500/20 border-blue-500';
    
    notification.className = `fixed top-4 right-4 z-50 px-4 py-3 rounded-lg border ${bgColor} text-white text-sm backdrop-blur-sm animation: slideInFromRight 0.3s ease-out;`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transition = 'opacity 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});
