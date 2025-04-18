/**
 * Create a donut chart
 * @param {string} elementId - ID of canvas element
 * @param {string} title - Chart title
 * @param {array} labels - Data labels
 * @param {array} data - Data values
 * @param {array} colors - Background colors
 */
function createDonutChart(elementId, title, labels, data, colors) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1,
                borderColor: 'rgba(255, 255, 255, 0.2)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: 'rgb(200, 200, 200)',
                        padding: 10,
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: title,
                    color: 'rgb(200, 200, 200)',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

/**
 * Create a bar chart
 * @param {string} elementId - ID of canvas element
 * @param {string} title - Chart title
 * @param {array} labels - Data labels
 * @param {array} data - Data values
 * @param {array} colors - Background colors
 */
function createBarChart(elementId, title, labels, data, colors) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: title,
                data: data,
                backgroundColor: colors,
                borderColor: 'rgba(255, 255, 255, 0.2)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: title,
                    color: 'rgb(200, 200, 200)',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Confidence: ${Math.round(context.raw)}%`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: 'rgb(200, 200, 200)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: 'rgb(200, 200, 200)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            animation: {
                duration: 1500
            }
        }
    });
}

/**
 * Create a line chart
 * @param {string} elementId - ID of canvas element
 * @param {string} title - Chart title
 * @param {array} labels - Data labels
 * @param {array} data - Data values
 * @param {string} color - Line color
 */
function createLineChart(elementId, title, labels, data, color) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: title,
                data: data,
                backgroundColor: color.replace('0.8', '0.2'),
                borderColor: color,
                borderWidth: 2,
                pointBackgroundColor: color,
                pointRadius: 3,
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: 'rgb(200, 200, 200)'
                    }
                },
                title: {
                    display: true,
                    text: title,
                    color: 'rgb(200, 200, 200)',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: 'rgb(200, 200, 200)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: 'rgb(200, 200, 200)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    beginAtZero: true
                }
            },
            animation: {
                duration: 1500
            }
        }
    });
}
