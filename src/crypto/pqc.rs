use crate::common::Error;

/// Post-quantum cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcAlgorithm {
    /// NIST standard: Kyber
    Kyber512,
    Kyber768,
    Kyber1024,
    /// NIST standard: Dilithium
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

impl PqcAlgorithm {
    /// Convert from string to algorithm
    pub fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "kyber512" => Ok(Self::Kyber512),
            "kyber768" => Ok(Self::Kyber768),
            "kyber1024" => Ok(Self::Kyber1024),
            "dilithium2" => Ok(Self::Dilithium2),
            "dilithium3" => Ok(Self::Dilithium3),
            "dilithium5" => Ok(Self::Dilithium5),
            _ => Err(Error::Internal(format!("Unsupported PQC algorithm: {}", s))),
        }
    }

    /// Convert to string
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Kyber512 => "Kyber512",
            Self::Kyber768 => "Kyber768",
            Self::Kyber1024 => "Kyber1024",
            Self::Dilithium2 => "Dilithium2",
            Self::Dilithium3 => "Dilithium3",
            Self::Dilithium5 => "Dilithium5",
        }
    }
}

/// Post-quantum cryptographic utilities
pub struct PqcUtils;

impl PqcUtils {
    /// Create a post-quantum CSR
    pub fn create_pqc_csr(
        common_name: &str,
        namespace: &str,
        dns_names: &[String],
        ip_addresses: &[String],
        pqc_algorithm: &str,
    ) -> Result<String, Error> {
        // Note: This is a simplified implementation
        // In a real implementation, we would use a library to generate a real CSR

        // Parse algorithm
        let algorithm = PqcAlgorithm::from_str(pqc_algorithm)?;

        // Create a mock CSR
        let alg_str = algorithm.to_str();
        let subject = format!("CN={}.{}", common_name, namespace);
        let spiffe_uri = format!("spiffe://{}/{}", namespace, common_name);

        // Add DNS and IP SANs
        let mut sans = Vec::new();
        for dns in dns_names {
            sans.push(format!("DNS:{}", dns));
        }

        for ip in ip_addresses {
            sans.push(format!("IP:{}", ip));
        }

        // Add SPIFFE URI
        sans.push(format!("URI:{}", spiffe_uri));

        let sans_str = sans.join(", ");

        Ok(format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n\
            MIIXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
            Algorithm: {}\n\
            Subject: {}\n\
            SANs: {}\n\
            -----END CERTIFICATE REQUEST-----",
            alg_str, subject, sans_str
        ))
    }

    /// Create a standard CSR
    pub fn create_standard_csr(
        common_name: &str,
        namespace: &str,
        dns_names: &[String],
        ip_addresses: &[String],
    ) -> Result<String, Error> {
        // Create a mock standard CSR
        let subject = format!("CN={}.{}", common_name, namespace);
        let spiffe_uri = format!("spiffe://{}/{}", namespace, common_name);

        // Add DNS and IP SANs
        let mut sans = Vec::new();
        for dns in dns_names {
            sans.push(format!("DNS:{}", dns));
        }

        for ip in ip_addresses {
            sans.push(format!("IP:{}", ip));
        }

        // Add SPIFFE URI
        sans.push(format!("URI:{}", spiffe_uri));

        let sans_str = sans.join(", ");

        Ok(format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n\
            MIIXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\
            Algorithm: RSA-SHA256\n\
            Subject: {}\n\
            SANs: {}\n\
            -----END CERTIFICATE REQUEST-----",
            subject, sans_str
        ))
    }

    /// Check if the algorithm is a post-quantum algorithm
    pub fn is_pqc_algorithm(algorithm: &str) -> bool {
        algorithm.to_lowercase().contains("kyber") ||
            algorithm.to_lowercase().contains("dilithium")
    }

    /// Get the recommended post-quantum algorithm
    pub fn get_recommended_algorithm() -> PqcAlgorithm {
        // Currently recommended by NIST
        PqcAlgorithm::Kyber768
    }
}