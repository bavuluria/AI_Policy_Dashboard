/**
 * Browser-based PII Parser
 * Detects and redacts personally identifiable information from text
 */

class PIIEntity {
    constructor(text, entityType, startPos, endPos, confidence = 1.0) {
        this.text = text;
        this.entityType = entityType;
        this.startPos = startPos;
        this.endPos = endPos;
        this.confidence = confidence;
    }
}

class DocumentPIIParser {
    constructor(redactionChar = "█") {
        this.redactionChar = redactionChar;
        this.piiPatterns = this.initializePIIPatterns();
        this.namePatterns = this.initializeNamePatterns();
        this.piiKeywords = new Set([
            'ssn', 'social security', 'ssn#', 'social security number',
            'passport', 'driver license', 'drivers license', 'dl#',
            'credit card', 'debit card', 'card number', 'account number',
            'routing number', 'bank account', 'iban', 'swift',
            'date of birth', 'dob', 'birthday', 'birth date',
            'maiden name', 'mother maiden', 'security question',
            'medical record', 'patient id', 'mrn', 'health insurance',
            'tax id', 'tin', 'ein', 'employee id'
        ]);
    }

    initializePIIPatterns() {
        return {
            // Social Security Numbers
            ssn: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
            
            // Phone Numbers (US format)
            phone: /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
            
            // Email Addresses
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            
            // Credit Card Numbers (various formats)
            credit_card: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
            
            // Driver License (generic pattern)
            drivers_license: /\b[A-Z]{1,2}\d{6,8}\b/g,
            
            // Passport Numbers (US format)
            passport: /\b[A-Z0-9]{6,9}\b/g,
            
            // Bank Account Numbers
            bank_account: /\b\d{8,17}\b/g,
            
            // IP Addresses
            ip_address: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
            
            // MAC Addresses
            mac_address: /\b[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}\b/g,
            
            // Date of Birth patterns
            date_of_birth: /\b(?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01])[/\-.]\d{4}\b|\b(?:0[1-9]|[12]\d|3[01])[/\-.](?:0[1-9]|1[0-2])[/\-.]\d{4}\b/g,
            
            // Address patterns (basic)
            address: /\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl)\b/gi,
            
            // Zip codes
            zip_code: /\b\d{5}(?:-\d{4})?\b/g
        };
    }

    initializeNamePatterns() {
        return {
            // Common name patterns
            full_name: /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/g,
            name_with_middle: /\b[A-Z][a-z]+\s+[A-Z]\.\s+[A-Z][a-z]+\b/g,
            name_with_title: /\b(?:Mr|Mrs|Ms|Dr|Prof)\.\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g,
            
            // Common organization patterns
            company: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Inc|LLC|Corp|Company|Co|Ltd|Corporation)\b/g,
            organization: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:University|College|School|Hospital|Bank|Group)\b/g,
            
            // Location patterns
            city_state: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,\s+[A-Z]{2}\b/g,
            country: /\b(?:United States|USA|Canada|Mexico|England|France|Germany|Japan|China|India)\b/g,
            
            // Money patterns
            currency: /\$[\d,]+(?:\.\d{2})?|\b\d+\s+dollars?\b/gi,
            
            // Date patterns (natural language)
            month_day_year: /\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/g
        };
    }

    extractTextFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                const content = e.target.result;
                const extension = file.name.split('.').pop().toLowerCase();
                
                switch (extension) {
                    case 'txt':
                        resolve(content);
                        break;
                    case 'csv':
                        resolve(this.parseCSV(content));
                        break;
                    case 'json':
                        try {
                            const jsonData = JSON.parse(content);
                            resolve(JSON.stringify(jsonData, null, 2));
                        } catch (error) {
                            reject(new Error('Invalid JSON file'));
                        }
                        break;
                    default:
                        // For other file types, try to extract as text
                        resolve(content);
                }
            };
            
            reader.onerror = () => reject(new Error('Failed to read file'));
            
            // Read file as text
            reader.readAsText(file);
        });
    }

    parseCSV(csvContent) {
        const lines = csvContent.split('\n');
        return lines.map(line => {
            // Simple CSV parsing - could be enhanced for complex CSV files
            return line.split(',').join(' ');
        }).join('\n');
    }

    detectPIIRegex(text) {
        const entities = [];
        
        for (const [piiType, pattern] of Object.entries(this.piiPatterns)) {
            // Reset regex lastIndex to ensure proper matching
            pattern.lastIndex = 0;
            
            let match;
            while ((match = pattern.exec(text)) !== null) {
                entities.push(new PIIEntity(
                    match[0],
                    piiType,
                    match.index,
                    match.index + match[0].length,
                    0.8
                ));
                
                // Prevent infinite loop with zero-length matches
                if (match.index === pattern.lastIndex) {
                    pattern.lastIndex++;
                }
            }
        }
        
        return entities;
    }

    detectPIINER(text) {
        const entities = [];
        
        for (const [entityType, pattern] of Object.entries(this.namePatterns)) {
            pattern.lastIndex = 0;
            
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const matchedText = match[0].trim();
                
                // Skip common words that might match name patterns
                const commonWords = ['Main Street', 'First Name', 'Last Name', 'Full Name', 'Company Name'];
                if (!commonWords.includes(matchedText) && matchedText.length > 2) {
                    entities.push(new PIIEntity(
                        matchedText,
                        `builtin_${entityType}`,
                        match.index,
                        match.index + matchedText.length,
                        0.7
                    ));
                }
                
                if (match.index === pattern.lastIndex) {
                    pattern.lastIndex++;
                }
            }
        }
        
        return entities;
    }

    detectPIIContextual(text) {
        const entities = [];
        const lines = text.split('\n');
        
        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            const line = lines[lineIdx];
            const lineLower = line.toLowerCase();
            
            // Look for PII keywords
            for (const keyword of this.piiKeywords) {
                if (lineLower.includes(keyword)) {
                    const keywordPos = lineLower.indexOf(keyword);
                    const afterKeyword = line.substring(keywordPos + keyword.length).trim();
                    
                    // Extract potential PII data after the keyword
                    const piiMatch = afterKeyword.match(/[:\s]+([A-Za-z0-9\-\s]{3,30})/);
                    if (piiMatch) {
                        const piiText = piiMatch[1].trim();
                        if (piiText.length > 2) {
                            const lineStartPos = text.indexOf(line);
                            const startPos = lineStartPos + keywordPos + keyword.length + piiMatch.index + 1;
                            entities.push(new PIIEntity(
                                piiText,
                                "contextual_pii",
                                startPos,
                                startPos + piiText.length,
                                0.6
                            ));
                        }
                    }
                }
            }
        }
        
        return entities;
    }

    detectAllPII(text) {
        const allEntities = [];
        
        // Regex-based detection
        allEntities.push(...this.detectPIIRegex(text));
        
        // NER-based detection
        allEntities.push(...this.detectPIINER(text));
        
        // Contextual detection
        allEntities.push(...this.detectPIIContextual(text));
        
        // Remove duplicates and overlapping entities
        return this.removeOverlappingEntities(allEntities);
    }

    removeOverlappingEntities(entities) {
        if (!entities.length) return entities;
        
        // Sort by start position
        entities.sort((a, b) => a.startPos - b.startPos);
        
        const filteredEntities = [];
        for (const entity of entities) {
            let overlaps = false;
            for (let i = 0; i < filteredEntities.length; i++) {
                const filteredEntity = filteredEntities[i];
                if (entity.startPos < filteredEntity.endPos && 
                    entity.endPos > filteredEntity.startPos) {
                    overlaps = true;
                    // If current entity has higher confidence, replace the filtered one
                    if (entity.confidence > filteredEntity.confidence) {
                        filteredEntities.splice(i, 1);
                        filteredEntities.push(entity);
                    }
                    break;
                }
            }
            
            if (!overlaps) {
                filteredEntities.push(entity);
            }
        }
        
        return filteredEntities;
    }

    redactPII(text, entities) {
        if (!entities.length) return text;
        
        // Sort entities by start position in reverse order to maintain positions
        entities.sort((a, b) => b.startPos - a.startPos);
        
        let redactedText = text;
        for (const entity of entities) {
            const redaction = this.redactionChar.repeat(entity.text.length);
            redactedText = redactedText.substring(0, entity.startPos) + 
                          redaction + 
                          redactedText.substring(entity.endPos);
        }
        
        return redactedText;
    }

    async processDocument(file) {
        try {
            const startTime = Date.now();
            
            // Extract text from file
            const originalText = await this.extractTextFromFile(file);
            
            // Detect PII
            const piiEntities = this.detectAllPII(originalText);
            
            // Calculate characters redacted
            let charactersRedacted = piiEntities.reduce((sum, entity) => sum + entity.text.length, 0);
            charactersRedacted = Math.min(charactersRedacted, originalText.length);
            
            // Redact PII
            const redactedText = this.redactPII(originalText, piiEntities);
            
            const processingTime = ((Date.now() - startTime) / 1000).toFixed(2);
            
            return {
                originalText,
                redactedText,
                entities: piiEntities,
                piiEntitiesFound: piiEntities.length,
                originalLength: originalText.length,
                redactedLength: redactedText.length,
                charactersRedacted,
                processingTime,
                report: this.generateDetailedReport(piiEntities, file.name)
            };
        } catch (error) {
            throw new Error(`Error processing document: ${error.message}`);
        }
    }

    generateDetailedReport(entities, fileName) {
        let report = `PII Detection and Redaction Report\n`;
        report += `=====================================\n\n`;
        report += `File: ${fileName}\n`;
        report += `PII entities found: ${entities.length}\n`;
        report += `Characters redacted: ${entities.reduce((sum, e) => sum + e.text.length, 0)}\n\n`;
        
        if (entities.length > 0) {
            report += `Detected PII Entities:\n`;
            report += `---------------------\n`;
            
            entities.forEach((entity, index) => {
                report += `${index + 1}. Type: ${entity.entityType}\n`;
                report += `   Text: ${entity.text}\n`;
                report += `   Confidence: ${entity.confidence.toFixed(2)}\n`;
                report += `   Position: ${entity.startPos}-${entity.endPos}\n\n`;
            });
        } else {
            report += `No PII entities detected.\n`;
        }
        
        return report;
    }

    downloadRedactedFile(text, originalFileName) {
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        const baseName = originalFileName.split('.')[0];
        a.href = url;
        a.download = `${baseName}_redacted.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// Export for use in HTML
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DocumentPIIParser, PIIEntity };
} else {
    window.DocumentPIIParser = DocumentPIIParser;
    window.PIIEntity = PIIEntity;
}
