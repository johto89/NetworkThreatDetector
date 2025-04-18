import re
import urllib.parse
from typing import Dict, List, Any, Set, Tuple
import logging
import tldextract
from models import ThreatCategoryEnum  # Ensure this import is correct

logger = logging.getLogger('web_phishing_detector')

class WebPhishingDetector:
    def __init__(self):
        # Enhanced lists for phishing detection
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often used in phishing
            '.xyz', '.win', '.top', '.loan', '.online',  # Suspicious generic TLDs
            '.stream', '.site', '.club', '.bid', 
            '.space', '.webcam', '.host', '.pw',  # Additional suspicious TLDs
            '.icu', '.live', '.uno', '.tech',
            # Additional high-risk TLDs
            '.info', '.cyou', '.asia', '.monster', '.casa', '.rest',
            '.bar', '.recipes', '.wiki', '.buzz', '.download'
        }
        
        # Enhanced suspicious domain names related to popular brands commonly targeted
        self.brand_related_keywords = {
            'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 
            'google', 'facebook', 'instagram', 'twitter', 'bank',
            'chase', 'wellsfargo', 'citibank', 'hsbc', 'barclays',
            'binance', 'coinbase', 'blockchain', 'steam', 'epic',
            'outlook', 'office365', 'onedrive', 'icloud', 'gmail',
            'yahoo', 'customer', 'service', 'support', 'help'
        }
        
        self.suspicious_keywords = {
            'login', 'signin', 'account', 'verify', 'update', 
            'secure', 'security', 'auth', 'authentication', 
            'confirm', 'validation', 'webscr', 'paypal', 
            'banking', 'wallet', 'payment', 'password', 
            'credential', 'recovery', 'reset', 'activate',
            # Additional phishing keywords
            'suspicious', 'unusual', 'verify-now', 'limited-time', 'expiration',
            'suspended', 'restricted', 'access-denied', 'verification-required',
            'urgent', 'important', 'alert', 'warning', 'notification',
            'security-check', 'billing-problem', 'invoice', 'statement',
            'update-required', 'subscription', 'review', 'compromised',
            'unauthorized', 'identity', 'document', 'ssn', 'tax',
            'irs', 'refund', 'prize', 'won', 'promotion', 'gift'
        }
        
        # Enhanced phishing patterns
        self.phishing_patterns = [
            r'https?://\d+\.\d+\.\d+\.\d+',  # IP-based URLs
            r'https?://[^/]+@',  # URLs with username/password in domain
            r'https?://[^/]+:\d+',  # URLs with non-standard ports
            r'https?://[^/]*\.(ml|tk|ga|cf|gq|xyz|win|top|loan|online|info|cyou)',  # Suspicious TLD pattern
            r'https?://(?:\w+\.)*[^.]+\.[a-z]{2,6}/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+',  # Complex suspicious URL structure
            r'https?://.*\.(?:com|org|net)\.[a-z]{2,6}',  # Triple extension domain
            r'https?://.*-(?:secure|login|signin|verify).*\..*',  # Dash with suspicious word
            r'https?://(?:www\.)?(?!paypal\.com).*paypal.*\..*',  # Brand phishing pattern
            r'https?://.*\.(php|html|aspx)\?.*(?:token|id|redirect|url)=',  # Suspicious parameter
            r'https?://.*bit\.ly.*',  # URL shorteners
            r'https?://.*(?:tiny|t|goo|is|ow)\.(?:url|ly|gl)',  # More URL shorteners
            r'https?://(?:www\.)?(?!microsoft\.com).*microsoft.*\..*',  # Microsoft phishing
            r'https?://(?:www\.)?(?!apple\.com).*apple.*\..*',  # Apple phishing
            r'https?://(?:www\.)?(?!google\.com).*google.*\..*',  # Google phishing
            r'https?://(?:www\.)?(?!amazon\.com).*amazon.*\..*',  # Amazon phishing
            r'https?://.{30,}',  # Excessively long URLs
            r'https?://.*\..*\..*\.[^.]{2,6}/.*',  # Multiple subdomain levels
            r'https?://.*[^\w\-.~:/\?#\[\]@!$&\'\(\)\*\+,;=%].*'  # URLs with unusual characters
        ]
        
        # Expanded suspicious user agent patterns
        self.suspicious_ua_patterns = [
            r'python-requests', r'curl', r'wget', 
            r'libwww', r'Apache-HttpClient', r'Go-http-client',
            r'HttpClient', r'Scrapy', r'Java/', r'Mozilla/\d\.\d \(compatible;',
            r'Wget', r'Curl', r'Fetch', r'Bot', r'Spider', r'Crawler',
            r'PhantomJS', r'HeadlessChrome', r'Headless', r'Phantom', 
            r'Selenium', r'WebDriver', r'Ruby', r'Rest-Client',
            r'(?:MSIE|Trident).{1,10}$',  # Old Internet Explorer or Trident versions
            r'^(?:Mozilla/5\.0)?$',  # Empty or partial user agent
            r'[Cc][Hh][Rr][Oo][Mm][Ee].{0,3}$',  # Suspicious Chrome version
            r'[Ff][Ii][Rr][Ee][Ff][Oo][Xx].{0,3}$'  # Suspicious Firefox version
        ]
        
        # Enhanced credential capture patterns
        self.credential_patterns = [
            r'username=', r'password=', r'email=', r'login_attempt',
            r'submit_credentials', r'authentication_token',
            r'userpass', r'user_pass', r'login_data', r'user_credentials',
            r'passwd=', r'pass=', r'pwd=', r'auth=', r'session=',
            r'account=', r'acct=', r'token=', r'apikey=', r'api_key=',
            r'secret=', r'user_?id=', r'customer_?id=', r'pin=',
            r'ssn=', r'social=', r'card_?number=', r'ccnumber=',
            r'verification=', r'cvv=', r'cvv2=', r'cvc=', r'verification_?code=',
            r'secure_?code=', r'access_?token=', r'refresh_?token=',
            r'authenticate', r'credentials', r'signin', r'signup',
            r'signon', r'passwd', r'pwd', r'psw', r'passcode',
            r'security_?answer', r'security_?question', r'mother_?maiden'
        ]
        
        # Domain reputation data - list of known legitimate domains
        # This would ideally be loaded from a constantly updated external source
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'youtube.com', 'netflix.com', 'paypal.com', 'gmail.com', 
            'yahoo.com', 'live.com', 'office.com', 'ebay.com', 'wikipedia.org',
            'adobe.com'
        }
        
        # Character deviation patterns (typosquatting)
        self.character_substitutions = {
            'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5',
            'b': '8', 'g': '9', 'q': '9'
        }
        
        # Misspelling detection for common domains
        self.common_misspellings = {
            'paypa1': 'paypal', 'g00gle': 'google', 'amaz0n': 'amazon',
            'micr0soft': 'microsoft', 'faceb00k': 'facebook',
            'appleid': 'apple', 'netf1ix': 'netflix', 'tw1tter': 'twitter',
            'yah00': 'yahoo', 'instaqram': 'instagram'
        }
        
        # ML feature weights (these would ideally be trained)
        self.feature_weights = {
            'suspicious_tld': 0.35,
            'ip_based_url': 0.45,
            'suspicious_keywords': 0.25,
            'phishing_patterns': 0.35,
            'non_https': 0.25,
            'suspicious_ua': 0.20,
            'unusual_method': 0.15,
            'credential_patterns': 0.35,
            'form_exfiltration': 0.30,
            'brand_mismatch': 0.40,
            'typosquatting': 0.40,
            'domain_age': 0.30,
            'redirect_count': 0.25,
            'url_length': 0.15,
            'subdomain_count': 0.20,
            'path_depth': 0.15,
            'parameter_count': 0.15
        }

    def _calculate_url_complexity(self, url: str) -> float:
        """
        Calculate URL complexity score based on multiple factors
        
        Args:
            url: The URL to analyze
            
        Returns:
            Complexity score (higher is more suspicious)
        """
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Count subdomains
            domain_parts = parsed.netloc.split('.')
            subdomain_count = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
            
            # Path depth
            path_parts = parsed.path.split('/')
            path_depth = len([p for p in path_parts if p])
            
            # Parameter count
            param_count = len(urllib.parse.parse_qs(parsed.query))
            
            # URL length factor
            length_factor = min(len(url) / 100, 1.0)
            
            # Calculate complexity score
            complexity = (
                (0.2 * subdomain_count) +
                (0.2 * path_depth) +
                (0.2 * param_count) +
                (0.4 * length_factor)
            )
            
            return min(complexity, 1.0)
        except:
            return 0.5  # Default for parsing errors

    def _check_typosquatting(self, domain: str) -> Tuple[bool, str, float]:
        """
        Check if domain appears to be typosquatting a legitimate domain
        
        Args:
            domain: Domain name to check
            
        Returns:
            Tuple of (is_typosquatting, target_domain, confidence)
        """
        # Extract root domain
        try:
            ext = tldextract.extract(domain)
            root_domain = f"{ext.domain}.{ext.suffix}"
        except:
            root_domain = domain
            
        # Check for direct misspellings
        for misspelling, target in self.common_misspellings.items():
            if misspelling in root_domain:
                return True, target, 0.9
        
        # Check for character substitutions
        normalized_domain = root_domain.lower()
        for char, substitute in self.character_substitutions.items():
            normalized_domain = normalized_domain.replace(substitute, char)
        
        # Check against trusted domains with Levenshtein distance
        for trusted in self.trusted_domains:
            # Simple edit distance check
            if self._levenshtein_distance(normalized_domain, trusted) <= 2:
                return True, trusted, 0.8
            # Check for insertion of dot
            if normalized_domain.replace('.', '') == trusted.replace('.', ''):
                return True, trusted, 0.95
        
        return False, "", 0.0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein (edit) distance between two strings
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def _extract_brand_from_url(self, url: str) -> Set[str]:
        """
        Extract potential brand names from URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Set of potential brand names found
        """
        found_brands = set()
        
        url_lower = url.lower()
        for brand in self.brand_related_keywords:
            if brand in url_lower:
                found_brands.add(brand)
                
        return found_brands

    def _analyze_domain_reputation(self, domain: str) -> float:
        """
        Analyze domain reputation score
        
        Args:
            domain: Domain to check
            
        Returns:
            Reputation score (0 = trustworthy, 1 = suspicious)
        """
        try:
            ext = tldextract.extract(domain)
            root_domain = f"{ext.domain}.{ext.suffix}"
            
            # Check against trusted domains
            if root_domain in self.trusted_domains:
                return 0.0
                
            # Check for brand mismatch (brand in domain but not matching trusted domain)
            brands = self._extract_brand_from_url(domain)
            for brand in brands:
                brand_domain = f"{brand}.com"
                if brand_domain in self.trusted_domains and root_domain != brand_domain:
                    return 0.9
            
            # Check for typosquatting
            is_typo, target, confidence = self._check_typosquatting(domain)
            if is_typo:
                return confidence
            
            # Check domain age (would require external API)
            # For now, return a moderate score for unknown domains
            return 0.5
            
        except Exception as e:
            logger.warning(f"Error in domain reputation analysis: {e}")
            return 0.5

    def detect_phishing(self, http_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect potential web phishing based on HTTP features
        
        Args:
            http_features: Dictionary of HTTP packet features
        
        Returns:
            Dictionary with phishing detection results
        """
        if not http_features or not isinstance(http_features, dict):
            return {'is_phishing': False, 'confidence': 0.0}
        
        # Extract relevant HTTP information
        uri = http_features.get('http_uri', '')
        host = http_features.get('http_host', '')
        method = http_features.get('http_method', '')
        user_agent = http_features.get('http_user_agent', '')
        payload = http_features.get('payload_str', '')
        referrer = http_features.get('http_referer', '')  # Added referrer check
        
        # Track feature scores and evidence
        feature_scores = {}
        evidence = []
        
        # 1. URL Composition Analysis
        try:
            parsed_url = urllib.parse.urlparse(uri)
            domain = parsed_url.netloc or host
            
            # If domain is still empty, try to extract from the URI
            if not domain and uri.startswith('http'):
                domain = uri.split('/')[2]
                
            # Check suspicious TLDs
            tld_match = False
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    tld_match = True
                    evidence.append(f"Suspicious TLD detected: {domain} ({tld})")
                    break
                    
            feature_scores['suspicious_tld'] = self.feature_weights['suspicious_tld'] if tld_match else 0.0
            
            # Check for IP-based URLs
            is_ip_based = bool(re.match(r'^\d+\.\d+\.\d+\.\d+', domain))
            if is_ip_based:
                evidence.append(f"IP-based URL detected: {domain}")
                feature_scores['ip_based_url'] = self.feature_weights['ip_based_url']
            else:
                feature_scores['ip_based_url'] = 0.0
                
            # URL complexity analysis
            complexity_score = self._calculate_url_complexity(uri)
            if complexity_score > 0.5:
                evidence.append(f"High URL complexity detected (score: {complexity_score:.2f})")
                
            feature_scores['url_length'] = self.feature_weights['url_length'] * (len(uri) > 100)
            
            # Subdomain analysis
            subdomain_parts = domain.split('.')
            feature_scores['subdomain_count'] = self.feature_weights['subdomain_count'] * (len(subdomain_parts) > 3)
            if len(subdomain_parts) > 3:
                evidence.append(f"Excessive subdomains detected: {domain}")
                
            # Path depth analysis
            path_parts = parsed_url.path.split('/')
            path_depth = len([p for p in path_parts if p])
            feature_scores['path_depth'] = self.feature_weights['path_depth'] * (path_depth > 3)
            
            # Parameter count analysis
            param_count = len(urllib.parse.parse_qs(parsed_url.query))
            feature_scores['parameter_count'] = self.feature_weights['parameter_count'] * (param_count > 5)
            
            # Domain reputation analysis
            reputation_score = self._analyze_domain_reputation(domain)
            if reputation_score > 0.7:
                evidence.append(f"Suspicious domain reputation: {domain}")
                
            # Brand mismatch check
            brands = self._extract_brand_from_url(uri)
            brand_mismatch = False
            
            for brand in brands:
                if domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
                    brand_mismatch = True
                    evidence.append(f"Brand name '{brand}' in URL doesn't match domain: {domain}")
            
            feature_scores['brand_mismatch'] = self.feature_weights['brand_mismatch'] if brand_mismatch else 0.0
            
            # Typosquatting check
            is_typo, target, typo_confidence = self._check_typosquatting(domain)
            if is_typo:
                evidence.append(f"Possible typosquatting detected: {domain} similar to {target}")
                feature_scores['typosquatting'] = self.feature_weights['typosquatting'] * typo_confidence
            else:
                feature_scores['typosquatting'] = 0.0
                
        except Exception as e:
            logger.warning(f"Error in URL analysis: {e}")
            # Fallback if URL parsing fails
            domain = host or uri
            feature_scores['suspicious_tld'] = 0.0
            feature_scores['ip_based_url'] = 0.0
            feature_scores['brand_mismatch'] = 0.0
            feature_scores['typosquatting'] = 0.0
        
        # 2. Suspicious Keyword Analysis
        url_suspicious_keywords = [kw for kw in self.suspicious_keywords if kw in uri.lower()]
        if url_suspicious_keywords:
            factor = min(len(url_suspicious_keywords) / 3.0, 1.0)  # Cap at 3 keywords
            feature_scores['suspicious_keywords'] = self.feature_weights['suspicious_keywords'] * factor
            evidence.append(f"Suspicious keywords found: {url_suspicious_keywords}")
        else:
            feature_scores['suspicious_keywords'] = 0.0
        
        # 3. Phishing Pattern Matching
        matched_patterns = []
        for i, pattern in enumerate(self.phishing_patterns):
            if re.search(pattern, uri, re.IGNORECASE):
                pattern_name = f"Pattern {i+1}"
                matched_patterns.append(pattern_name)
                
        if matched_patterns:
            factor = min(len(matched_patterns) / 3.0, 1.0)  # Cap at 3 patterns
            feature_scores['phishing_patterns'] = self.feature_weights['phishing_patterns'] * factor
            evidence.append(f"Matched suspicious URL patterns: {matched_patterns}")
        else:
            feature_scores['phishing_patterns'] = 0.0
        
        # 4. HTTPS Status Check
        if not uri.startswith('https://') and uri.startswith('http://'):
            feature_scores['non_https'] = self.feature_weights['non_https']
            evidence.append("Non-HTTPS URL detected")
        else:
            feature_scores['non_https'] = 0.0
        
        # 5. User Agent Analysis
        if user_agent:
            suspicious_ua_match = [
                pattern for pattern in self.suspicious_ua_patterns 
                if re.search(pattern, user_agent, re.IGNORECASE)
            ]
            if suspicious_ua_match:
                feature_scores['suspicious_ua'] = self.feature_weights['suspicious_ua']
                evidence.append(f"Suspicious User-Agent detected: {suspicious_ua_match}")
            else:
                feature_scores['suspicious_ua'] = 0.0
        else:
            # Missing user agent is suspicious
            feature_scores['suspicious_ua'] = self.feature_weights['suspicious_ua'] * 0.5
            evidence.append("Missing User-Agent")
        
        # 6. Method and Payload Analysis
        # Unusual HTTP methods
        if method and method.upper() not in ['GET', 'POST', 'HEAD']:
            feature_scores['unusual_method'] = self.feature_weights['unusual_method']
            evidence.append(f"Unusual HTTP Method: {method}")
        else:
            feature_scores['unusual_method'] = 0.0
        
        # Credential capture pattern detection in payload
        if payload:
            credential_matches = [
                pattern for pattern in self.credential_patterns 
                if re.search(pattern, payload, re.IGNORECASE)
            ]
            if credential_matches:
                factor = min(len(credential_matches) / 3.0, 1.0)  # Cap at 3 matches
                feature_scores['credential_patterns'] = self.feature_weights['credential_patterns'] * factor
                evidence.append(f"Credential capture patterns detected: {credential_matches}")
            else:
                feature_scores['credential_patterns'] = 0.0
        else:
            feature_scores['credential_patterns'] = 0.0
        
        # 7. Additional Heuristics
        # Check for potential form data exfiltration
        if payload and ('content-type: application/x-www-form-urlencoded' in payload.lower() or 
                      'content-type: multipart/form-data' in payload.lower()):
            feature_scores['form_exfiltration'] = self.feature_weights['form_exfiltration']
            evidence.append("Potential form data exfiltration detected")
        else:
            feature_scores['form_exfiltration'] = 0.0
            
        # 8. Referrer analysis
        if referrer:
            # Check if referrer domain matches the current domain
            try:
                referrer_domain = urllib.parse.urlparse(referrer).netloc
                if domain and referrer_domain and referrer_domain != domain:
                    evidence.append(f"Referrer domain mismatch: {referrer_domain} -> {domain}")
            except:
                pass
        
        # 9. Redirect chain analysis
        redirect_count = http_features.get('redirect_count', 0)
        if redirect_count > 1:
            feature_scores['redirect_count'] = self.feature_weights['redirect_count'] * min(redirect_count / 3.0, 1.0)
            evidence.append(f"Multiple redirects detected: {redirect_count}")
        else:
            feature_scores['redirect_count'] = 0.0
        
        # Calculate weighted phishing score
        phishing_score = sum(feature_scores.values())
        
        # Apply logistic function to get confidence between 0 and 1
        # This helps to normalize the score and handle extreme values
        confidence = 1.0 / (1.0 + 2.71828 ** (-1.5 * (phishing_score - 0.5)))
        
        return {
            'is_phishing': confidence > 0.60,  # Lower threshold for higher sensitivity
            'confidence': confidence,
            'evidence': evidence,
            'feature_scores': feature_scores,
            'suspicious_elements': {
                'domain': domain,
                'suspicious_keywords': url_suspicious_keywords,
                'matched_patterns': matched_patterns,
                'brands_found': list(self._extract_brand_from_url(uri)) if uri else []
            }
        }
    
    def analyze_http_traffic(self, packet_features: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a list of packet features for web phishing
        
        Args:
            packet_features: List of packet feature dictionaries
        
        Returns:
            Dictionary with overall phishing analysis results
        """
        if not packet_features:
            return {
                'total_packets': 0,
                'phishing_detected': False,
                'phishing_count': 0,
                'phishing_confidence': 0.0,
                'phishing_details': []
            }
        
        phishing_packets = []
        
        # Improved HTTP packet filtering with deeper inspection
        http_packets = []
        for p in packet_features:
            # Check for HTTP indicators
            if (p.get('has_http', False) or 
                p.get('protocol_name') == 'HTTP' or 
                (p.get('dst_port') in [80, 443, 8080, 8443] and p.get('payload_str'))):
                
                # Further inspect payload for HTTP patterns
                payload = p.get('payload_str', '')
                if payload and (
                    payload.startswith('GET ') or 
                    payload.startswith('POST ') or 
                    payload.startswith('HTTP/') or
                    'Host:' in payload or
                    'User-Agent:' in payload or
                    'Content-Type:' in payload
                ):
                    http_packets.append(p)
                else:
                    # If basic HTTP indicators are there, include anyway
                    if p.get('has_http', False) or p.get('protocol_name') == 'HTTP':
                        http_packets.append(p)
        
        # Build traffic context for more accurate analysis
        traffic_context = self._build_traffic_context(http_packets)
        
        # Analyze each HTTP packet with context
        for packet in http_packets:
            # Enhance packet with context information
            packet_with_context = self._enrich_packet_with_context(packet, traffic_context)
            
            # Detect phishing
            phishing_result = self.detect_phishing(packet_with_context)
            
            if phishing_result['is_phishing']:
                phishing_packets.append({
                    'packet': packet,
                    'phishing_details': phishing_result
                })
        
        # Calculate overall phishing statistics
        total_http_packets = len(http_packets)
        phishing_count = len(phishing_packets)
        
        # Calculate confidence levels
        if phishing_packets:
            # Weight by both count and confidence
            avg_confidence = sum(p['phishing_details']['confidence'] for p in phishing_packets) / phishing_count
            # Adjust confidence based on proportion of phishing packets
            proportion_factor = min(phishing_count / max(total_http_packets, 1), 1.0)
            adjusted_confidence = avg_confidence * (0.7 + 0.3 * proportion_factor)
        else:
            avg_confidence = 0.0
            adjusted_confidence = 0.0
        
        return {
            'total_packets': total_http_packets,
            'phishing_detected': phishing_count > 0,
            'phishing_count': phishing_count,
            'phishing_confidence': adjusted_confidence,
            'phishing_details': phishing_packets,
            'traffic_summary': self._summarize_traffic(http_packets, phishing_packets)
        }

    def _build_traffic_context(self, http_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build traffic context from all HTTP packets for more accurate analysis
        
        Args:
            http_packets: List of HTTP packet dictionaries
            
        Returns:
            Dictionary with traffic context information
        """
        # Track domains, redirect chains, and form submissions
        domains = {}
        redirect_chains = []
        current_chain = []
        form_submissions = []
        
        for packet in http_packets:
            # Extract domain information
            uri = packet.get('http_uri', '')
            host = packet.get('http_host', '')
            
            try:
                if uri.startswith('http'):
                    domain = urllib.parse.urlparse(uri).netloc
                else:
                    domain = host
                
                # Track domain frequency
                if domain:
                    if domain in domains:
                        domains[domain] += 1
                    else:
                        domains[domain] = 1
            except:
                pass
            
            # Track redirect chains
            status_code = packet.get('http_status', 0)
            if 300 <= status_code <= 399:  # Redirect status codes
                if current_chain:
                    current_chain.append(packet)
                else:
                    current_chain = [packet]
            else:
                if current_chain:
                    current_chain.append(packet)
                    redirect_chains.append(current_chain)
                    current_chain = []
            
            # Track form submissions
            method = packet.get('http_method', '')
            payload = packet.get('payload_str', '')
            
            if method == 'POST' and payload:
                if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.credential_patterns):
                    form_submissions.append(packet)
        
        # If redirect chain still in progress at the end, add it
        if current_chain:
            redirect_chains.append(current_chain)
            
        return {
            'domains': domains,
            'redirect_chains': redirect_chains,
            'form_submissions': form_submissions,
            'most_common_domain': max(domains.items(), key=lambda x: x[1])[0] if domains else None,
            'unique_domain_count': len(domains)
        }

    def _enrich_packet_with_context(self, packet: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich HTTP packet with context information for better detection
        
        Args:
            packet: HTTP packet dictionary
            context: Traffic context information
            
        Returns:
            Enriched packet dictionary
        """
        enriched_packet = packet.copy()
        
        # Extract domain
        uri = packet.get('http_uri', '')
        host = packet.get('http_host', '')
        
        try:
            if uri.startswith('http'):
                domain = urllib.parse.urlparse(uri).netloc
            else:
                domain = host
                
            # Count redirects to this domain
            redirect_count = sum(1 for chain in context['redirect_chains'] 
                              for p in chain 
                              if p.get('http_uri', '').find(domain) >= 0)
                
            enriched_packet['redirect_count'] = redirect_count
            
            # Check if domain is rare in the traffic
            if domain in context['domains']:
                domain_frequency = context['domains'][domain]
                enriched_packet['domain_frequency'] = domain_frequency
                enriched_packet['is_rare_domain'] = domain_frequency == 1 and context['unique_domain_count'] > 1
        except:
            enriched_packet['redirect_count'] = 0
            enriched_packet['domain_frequency'] = 0
            enriched_packet['is_rare_domain'] = False
            
        return enriched_packet

    def _summarize_traffic(self, http_packets: List[Dict[str, Any]], 
                          phishing_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create a summary of the traffic patterns for reporting
        
        Args:
            http_packets: List of all HTTP packets
            phishing_packets: List of detected phishing packets
            
        Returns:
            Traffic summary dictionary
        """
        # Extract domains from phishing packets
        phishing_domains = set()
        for p in phishing_packets:
            packet = p['packet']
            uri = packet.get('http_uri', '')
            host = packet.get('http_host', '')
            
            try:
                if uri.startswith('http'):
                    domain = urllib.parse.urlparse(uri).netloc
                else:
                    domain = host
                    
                if domain:
                    phishing_domains.add(domain)
            except:
                pass
                
        # Count HTTP methods
        methods = {}
        for p in http_packets:
            method = p.get('http_method', '')
            if method:
                if method in methods:
                    methods[method] += 1
                else:
                    methods[method] = 1
        
        # Count response status codes
        status_codes = {}
        for p in http_packets:
            status = p.get('http_status')
            if status:
                status_group = f"{status // 100}XX"
                if status_group in status_codes:
                    status_codes[status_group] += 1
                else:
                    status_codes[status_group] = 1
                    
        return {
            'phishing_domains': list(phishing_domains),
            'http_methods': methods,
            'status_codes': status_codes,
            'total_domains': len(set(urllib.parse.urlparse(p.get('http_uri', '')).netloc 
                                    for p in http_packets if p.get('http_uri', '').startswith('http')))
        }

def detect_web_phishing(packet_features):
    """
    Wrapper function for web phishing detection to integrate with existing systems
    
    Args:
        packet_features: List of packet feature dictionaries
    
    Returns:
        Dictionary with web phishing detection results or None
    """
    try:
        detector = WebPhishingDetector()
        phishing_analysis = detector.analyze_http_traffic(packet_features)
        
        # Transform results into a threat detection format
        if phishing_analysis['phishing_detected']:
            # Extract evidence details
            evidence_details = []
            for i, phish_packet in enumerate(phishing_analysis['phishing_details'][:5]):  # Limit to first 5
                detail = phish_packet['phishing_details']['evidence']
                evidence_details.append(f"Packet {i+1}: {', '.join(detail[:3])}")  # Limit to first 3 evidence items
            
            # Categorize the severity based on confidence
            confidence = phishing_analysis['phishing_confidence']
            severity = "Critical" if confidence > 0.85 else "High" if confidence > 0.7 else "Medium"
            
            # Create a more detailed description based on findings
            descriptions = {
                "Critical": "Highly sophisticated web phishing attack detected with multiple deception techniques.",
                "High": "Advanced web phishing attempt detected with targeted brand impersonation.",
                "Medium": "Potential web phishing activity detected with suspicious characteristics."
            }
            
            return {
                'name': ThreatCategoryEnum.WEB_PHISHING,
                'type': 'network',
                'confidence': phishing_analysis['phishing_confidence'],
                'severity': severity,
                'description': descriptions[severity],
                'evidence_count': phishing_analysis['phishing_count'],
                'indicators': [
                    f"Total HTTP packets analyzed: {phishing_analysis['total_packets']}",
                    f"Phishing packets detected: {phishing_analysis['phishing_count']}",
                    f"Confidence level: {phishing_analysis['phishing_confidence']:.2%}",
                    f"Targeted domains: {', '.join(phishing_analysis['traffic_summary']['phishing_domains'][:3]) if phishing_analysis['traffic_summary']['phishing_domains'] else 'Unknown'}"
                ],
                'evidence_details': evidence_details,
                'details': phishing_analysis
            }
        
        return None
    
    except Exception as e:
        logger.error(f"Web phishing detection error: {e}")
        return None