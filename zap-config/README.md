# OWASP ZAP Configuration

This directory contains configuration files for OWASP ZAP (Zed Attack Proxy) integration with the Moderor API Compliance Tool.

## 📁 Directory Structure

```
zap-config/
├── policies/
│   └── api-security-policy.policy    # Custom API security scanning policy
└── README.md                        # This documentation file
```

## 🔧 API Security Policy Configuration

The `api-security-policy.policy` file defines a comprehensive security scanning policy specifically tailored for API testing, focusing on the OWASP API Security Top 10 vulnerabilities.

### 📋 Enabled Security Checks

#### 🔴 HIGH Priority (Critical Vulnerabilities)
- **SQL Injection** (40018, 40019, 40020, 40021)
  - Detects various SQL injection attack vectors
  - Includes time-based, boolean-based, and error-based injections

- **Cross-Site Scripting (XSS)** (40012, 40014, 40016, 40017)
  - Reflected, stored, and DOM-based XSS detection
  - Includes advanced payload variations

- **Authentication Issues** (10105, 10106)
  - Weak authentication mechanisms
  - Authentication bypass attempts

- **Authorization Flaws** (40013)
  - Broken access control
  - Privilege escalation attempts

- **OWASP API Top 10 Specific:**
  - **Broken Object Level Authorization** (40039) - IDOR vulnerabilities
  - **Broken User Authentication** (40027) - Authentication weaknesses
  - **Injection Attacks** (40008, 40009) - Various injection types

#### 🟡 MEDIUM Priority (Important Issues)
- **Information Disclosure** (10024, 10025)
  - Sensitive data exposure
  - Debug information leakage

- **Excessive Data Exposure** (40029)
  - API responses containing too much data
  - Privacy violations

- **Rate Limiting Issues** (40040)
  - Missing or insufficient rate limiting
  - Potential DoS vulnerabilities

- **Security Misconfiguration** (10047, 10048)
  - Default configurations
  - Exposed sensitive endpoints

## 🎯 Coverage Areas

### OWASP API Security Top 10 Mapping

| OWASP Category | Policy Coverage | Alert Level |
|----------------|----------------|-------------|
| API1:2023 - Broken Object Level Authorization | ✅ Full Coverage | HIGH |
| API2:2023 - Broken Authentication | ✅ Full Coverage | HIGH |
| API3:2023 - Broken Object Property Level Authorization | ✅ Full Coverage | HIGH |
| API4:2023 - Unrestricted Resource Consumption | ✅ Full Coverage | MEDIUM |
| API5:2023 - Broken Function Level Authorization | ✅ Full Coverage | HIGH |
| API6:2023 - Unrestricted Access to Sensitive Business Flows | ✅ Partial Coverage | MEDIUM |
| API7:2023 - Server Side Request Forgery | ✅ Full Coverage | HIGH |
| API8:2023 - Security Misconfiguration | ✅ Full Coverage | MEDIUM |
| API9:2023 - Improper Inventory Management | ✅ Partial Coverage | MEDIUM |
| API10:2023 - Unsafe Consumption of APIs | ✅ Full Coverage | HIGH |

## ⚙️ Configuration Details

### Policy Structure
```xml
<configuration>
    <policy>API Security Scanning Policy</policy>
    <scanner>
        <policy id="RULE_ID" level="PRIORITY" />
    </scanner>
</configuration>
```

### Alert Levels
- **HIGH**: Critical security issues requiring immediate attention
- **MEDIUM**: Important security issues that should be addressed
- **LOW**: Minor issues or informational findings

### Rule IDs Explained
- **400xx**: Active scanning rules (attack-based testing)
- **100xx**: Passive scanning rules (response analysis)
- **101xx**: Authentication and session management

## 🚀 Integration with Moderor

### Docker Compose Integration
```yaml
zap-scanner:
  image: ghcr.io/zaproxy/zaproxy:stable
  volumes:
    - ./zap-config:/zap/config:ro
    - zap_reports:/zap/reports:rw
  command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

### MCP Server Usage
The MCP server automatically:
1. Loads this policy configuration
2. Applies it to all security scans
3. Maps findings to OWASP categories
4. Generates compliance reports

### Scan Execution Flow
1. **Spider Phase**: Discovers API endpoints
2. **Active Scan**: Runs enabled security checks
3. **Passive Scan**: Analyzes responses for additional issues
4. **Report Generation**: Maps findings to compliance categories

## 📊 Expected Results

### Typical Scan Findings
- **SQL Injection**: Database query manipulation attempts
- **XSS**: JavaScript injection in API responses
- **Authentication Bypass**: Weak auth mechanisms
- **IDOR**: Direct object reference vulnerabilities
- **Rate Limiting**: Missing API throttling
- **Information Disclosure**: Sensitive data exposure

### Compliance Scoring
- **90-100%**: Excellent API security posture
- **75-89%**: Good security with minor issues
- **50-74%**: Moderate security requiring attention
- **0-49%**: Critical security issues present

## 🔧 Customization

### Adding New Rules
```xml
<policy id="NEW_RULE_ID" level="HIGH|MEDIUM|LOW" />
```

### Modifying Alert Levels
- Increase level for more critical rules
- Decrease level for less important rules
- Set to OFF to disable specific checks

### Performance Tuning
- Reduce HIGH priority rules for faster scans
- Increase MEDIUM rules for comprehensive coverage
- Balance speed vs. thoroughness based on needs

## 📈 Monitoring & Maintenance

### Regular Updates
- Review new ZAP rule additions quarterly
- Update policy for emerging threats
- Test policy against known vulnerable applications

### Performance Optimization
- Monitor scan execution times
- Adjust rule priorities based on false positives
- Optimize for specific API architectures (REST, GraphQL, SOAP)

### Compliance Validation
- Test against OWASP API Security Top 10
- Validate against industry standards
- Regular policy effectiveness reviews

## 🆘 Troubleshooting

### Common Issues
- **False Positives**: Adjust rule thresholds or disable problematic rules
- **Scan Timeouts**: Reduce rule count or increase timeout values
- **Authentication Issues**: Verify API authentication configuration
- **Network Errors**: Check connectivity between containers

### Debug Mode
Enable detailed logging in docker-compose.yml:
```yaml
command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config log.level=DEBUG
```

## 📚 Additional Resources

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [ZAP Rule Documentation](https://www.zaproxy.org/docs/alerts/)
- [Docker ZAP Image](https://github.com/zaproxy/zaproxy)

---

This configuration provides comprehensive API security testing while maintaining reasonable scan performance and accuracy.
