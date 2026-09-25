@"

\# NetOps AI SOC



\*\*AI-Powered Network Operations \& Security Monitoring Platform\*\*



NetOps AI SOC is a real-time network monitoring and security detection platform that combines network flow collection, machine-learning-based traffic analysis, rule-based detection, risk scoring, alert persistence, and incident ticketing into a single Streamlit dashboard.



The project is designed as a practical NetOps/SecOps demonstration, showing how network telemetry can be collected, analyzed, converted into security alerts, and presented through an operational SOC-style interface.



\---



\## Features



\- Real-time network flow collection

\- Live ML-based traffic prediction

\- Hybrid network anomaly detection

\- Rule-based security detection

\- Risk scoring

\- Persistent SQLite alert database

\- Alert deduplication

\- Security alert classification

\- SOC-style monitoring dashboard

\- Real-time system health indicators

\- Security statistics and risk summaries

\- Incident ticket creation and management

\- New-ticket notification support

\- Automatic dashboard refresh

\- Historical alert visibility

\- Trained Random Forest hybrid classifier



\---



\## Architecture



```text

&#x20;                   Network Traffic

&#x20;                         |

&#x20;                         v

&#x20;               +-------------------+

&#x20;               |  Flow Collector   |

&#x20;               |     Scapy         |

&#x20;               +---------+---------+

&#x20;                         |

&#x20;                         v

&#x20;               live\_network\_flows.csv

&#x20;                         |

&#x20;            +------------+------------+

&#x20;            |                         |

&#x20;            v                         v

&#x20;   +------------------+      +-------------------+

&#x20;   | ML Prediction    |      | Detection Engine  |

&#x20;   | Engine           |      |                   |

&#x20;   | Random Forest    |      | Rule-based        |

&#x20;   | Hybrid Model     |      | Detection         |

&#x20;   +--------+---------+      +---------+---------+

&#x20;            |                          |

&#x20;            +------------+-------------+

&#x20;                         |

&#x20;                         v

&#x20;                 Risk \& Alert Engine

&#x20;                         |

&#x20;                         v

&#x20;                 +---------------+

&#x20;                 | SQLite DB     |

&#x20;                 | Alerts/Tickets|

&#x20;                 +-------+-------+

&#x20;                         |

&#x20;                         v

&#x20;                 +---------------+

&#x20;                 | Streamlit SOC |

&#x20;                 | Dashboard     |

&#x20;                 +---------------+

