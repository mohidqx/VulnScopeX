# SHODAN VulnScopeX Live Web Application Package
__version__ = "6.0 Enterprise"
__author__ = "SHODAN Team"

import emoji

# Import all advanced feature modules (70 hacker-grade features)
try:
    from .advanced_exploitation import (
        ExploitationChainBuilder, PrivilegeEscalationHunter, LateralMovementMapper,
        VulnerabilityChaining, AttackSurfaceMapper, BackdoorDetection,
        ZeroDayAnalysis, PostExploitationFramework, BehavioralAnomalyDetection,
        AIExploitPrediction
    )
    from .advanced_reconnaissance import (
        DNSIntelligence, PortFingerprinting, ProtocolAnalysis, BannerGrabbingAdvanced,
        WebCrawlerIntelligence, ServiceVersionDetection, SubdomainEnumeration,
        GeolocationMapping, NetworkTopologyReconstruction, AssetDiscoveryEngine
    )
    from .advanced_cryptography import (
        SSLTLSAnalysis, WeakCipherDetection, KeyExtractionVectors,
        CryptographicDowngradeDetection, PaddingOracleDetection, CertificatePinningBypass,
        CryptographicSideChannelDetection, CryptographicMaterialLeakage,
        MasterKeyDiscovery, FastPathCryptoVulnerabilities
    )
    from .advanced_web_apps import (
        BlindSQLiHunter, TemplateInjectionDetection, ExpressionLanguageInjection,
        XXEInjectionAdvanced, SSRFExploitationMapper, OpenRedirectChaining,
        GraphQLInjectionDetection, APIKeyExposureDetector, MicroserviceCommunicationFlaws,
        WebSocketHijackingDetection
    )
    from .advanced_network import (
        DNSSpoofingSimulator, BGPHijackingAnalysis, DHCPStarvationDetection,
        ARPSpoofingMapper, ManInTheMiddleVulnerabilities, DDoSAttackVectorAnalysis,
        IPFragmentationAttacks, TCPIPStackExploitation, VPNVulnerabilityAssessment,
        NetworkSegmentationBypass
    )
    from .advanced_privilege_escalation import (
        KernelExploitMapper, DriverVulnerabilityAnalysis, UEFIBIOSBackdoorDetection,
        UACBypassTechniques, SudoMisconfigurationHunter, SUIDBinaryAnalysis,
        DirectoryPermissionAbuse, CapabilityBasedPrivilegeEscalation, TokenImpersonationDetector,
        RaceConditionDetection
    )
    from .advanced_memory import (
        MemoryCorruptionExploitFinder, HeapSprayDetection, ROPGadgetDiscovery,
        FormatStringVulnerabilityHunter, CodeInjectionMapper, ProcessHollowinDetection,
        ReflectiveDLLInjection, ControlFlowGuardBypass, ReturnSpaceHijacking,
        ASLRBypassTechniques
    )
except ImportError as e:
    print(f"⚠️ Warning: Some advanced modules could not be imported: {e}")
