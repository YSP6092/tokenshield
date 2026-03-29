/**
 * TokenShield Device Fingerprinting Library
 * Captures comprehensive device and browser metadata for threat detection
 */

class DeviceFingerprint {
    constructor() {
        this.metadata = {};
    }
    
    /**
     * Collect all device fingerprinting data
     */
    async collect() {
        // Screen information
        this.metadata.screen_width = screen.width;
        this.metadata.screen_height = screen.height;
        this.metadata.screen_depth = screen.colorDepth;
        this.metadata.pixel_ratio = window.devicePixelRatio;
        
        // Timezone
        this.metadata.timezone_offset = new Date().getTimezoneOffset();
        this.metadata.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        
        // Language
        this.metadata.language = navigator.language;
        this.metadata.languages = navigator.languages;
        
        // Platform
        this.metadata.platform = navigator.platform;
        this.metadata.user_agent = navigator.userAgent;
        
        // Hardware concurrency (CPU cores)
        this.metadata.cpu_cores = navigator.hardwareConcurrency || null;
        
        // Device memory (if available)
        this.metadata.memory = navigator.deviceMemory || null;
        
        // Do Not Track
        this.metadata.do_not_track = navigator.doNotTrack;
        
        // Plugins (deprecated but still useful)
        this.metadata.plugins = this.getPlugins();
        
        // Canvas fingerprint
        this.metadata.canvas_fingerprint = this.getCanvasFingerprint();
        
        // WebGL fingerprint
        this.metadata.webgl_fingerprint = this.getWebGLFingerprint();
        
        // Audio fingerprint
        this.metadata.audio_fingerprint = await this.getAudioFingerprint();
        
        // Fonts
        this.metadata.fonts = this.getFonts();
        
        // Ad blocker detection
        this.metadata.ad_blocker = await this.detectAdBlocker();
        
        // Geolocation (if permitted)
        this.metadata.geolocation = await this.getGeolocation();
        
        return this.metadata;
    }
    
    /**
     * Get installed plugins
     */
    getPlugins() {
        const plugins = [];
        for (let i = 0; i < navigator.plugins.length; i++) {
            plugins.push(navigator.plugins[i].name);
        }
        return plugins.slice(0, 10); // Limit to first 10
    }
    
    /**
     * Generate canvas fingerprint
     */
    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // Draw text with specific styling
            ctx.textBaseline = 'top';
            ctx.font = '14px "Arial"';
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('TokenShield 🛡️', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Security Engine', 4, 17);
            
            // Convert to data URL and hash
            const dataURL = canvas.toDataURL();
            return this.hashString(dataURL);
        } catch (e) {
            return null;
        }
    }
    
    /**
     * Generate WebGL fingerprint
     */
    getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) return null;
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            
            return this.hashString(vendor + '|' + renderer);
        } catch (e) {
            return null;
        }
    }
    
    /**
     * Generate audio fingerprint
     */
    async getAudioFingerprint() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) return null;
            
            const context = new AudioContext();
            const oscillator = context.createOscillator();
            const analyser = context.createAnalyser();
            const gainNode = context.createGain();
            const scriptProcessor = context.createScriptProcessor(4096, 1, 1);
            
            gainNode.gain.value = 0; // Mute
            oscillator.type = 'triangle';
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(context.destination);
            
            oscillator.start(0);
            
            return new Promise((resolve) => {
                scriptProcessor.onaudioprocess = function(event) {
                    const output = event.outputBuffer.getChannelData(0);
                    const fingerprint = output.slice(0, 30).join('');
                    oscillator.stop();
                    scriptProcessor.disconnect();
                    gainNode.disconnect();
                    analyser.disconnect();
                    resolve(this.hashString(fingerprint));
                }.bind(this);
                
                setTimeout(() => resolve(null), 1000); // Timeout after 1s
            });
        } catch (e) {
            return null;
        }
    }
    
    /**
     * Detect installed fonts
     */
    getFonts() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Verdana', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Bookman',
            'Trebuchet MS', 'Impact', 'Lucida Console'
        ];
        
        const detectedFonts = [];
        
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        
        const baselines = {};
        for (const baseFont of baseFonts) {
            ctx.font = testSize + ' ' + baseFont;
            baselines[baseFont] = ctx.measureText(testString).width;
        }
        
        for (const testFont of testFonts) {
            let detected = false;
            for (const baseFont of baseFonts) {
                ctx.font = testSize + ' ' + testFont + ',' + baseFont;
                const width = ctx.measureText(testString).width;
                if (width !== baselines[baseFont]) {
                    detected = true;
                    break;
                }
            }
            if (detected) {
                detectedFonts.push(testFont);
            }
        }
        
        return detectedFonts;
    }
    
    /**
     * Detect ad blocker
     */
    async detectAdBlocker() {
        try {
            // Try to fetch a common ad script
            await fetch('https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js', {
                method: 'HEAD',
                mode: 'no-cors'
            });
            return false; // No ad blocker
        } catch (e) {
            return true; // Ad blocker detected
        }
    }
    
    /**
     * Get geolocation if permitted
     */
    async getGeolocation() {
        if (!navigator.geolocation) {
            return { permission: 'not_supported' };
        }
        
        return new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    resolve({
                        permission: 'granted',
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy
                    });
                },
                (error) => {
                    resolve({
                        permission: 'denied',
                        error: error.message
                    });
                },
                { timeout: 5000 }
            );
        });
    }
    
    /**
     * Hash string using simple hash function
     */
    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(16);
    }
    
    /**
     * Send fingerprint data to threat detection API
     */
    async sendToThreatDetection(actionType, endpoint) {
        try {
            const metadata = await this.collect();
            
            const response = await fetch('/api/security/threat-detect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + localStorage.getItem('token')
                },
                body: JSON.stringify({
                    ...metadata,
                    action_type: actionType,
                    endpoint: endpoint
                })
            });
            
            const data = await response.json();
            
            // Handle high threat
            if (data.session_status && data.session_status.should_revoke) {
                console.warn('⚠️ High threat detected - session will be revoked');
                // Trigger logout modal or additional verification
                if (window.handleSecurityThreat) {
                    window.handleSecurityThreat(data.threat_analysis);
                }
            } else if (data.session_status && data.session_status.should_challenge) {
                console.warn('⚠️ Medium threat detected - additional verification may be required');
            }
            
            return data;
        } catch (error) {
            console.error('Threat detection error:', error);
            return null;
        }
    }
}

// Global instance
window.DeviceFingerprint = new DeviceFingerprint();

// Auto-send on page load for authenticated pages
if (localStorage.getItem('token')) {
    setTimeout(() => {
        window.DeviceFingerprint.sendToThreatDetection('page_load', window.location.pathname);
    }, 1000); // Delay to allow page to load
}