#[allow(unused)]
pub mod fs_consts {
  const BASE_URL: &str = "https://www.filescan.io/";
  
  pub mod scan {
    const S_FILE: &str = "/api/scan/file";
    const S_URL: &str = "/api/scan/url";
    const S_REPORT: &str = "/api/scan/{flow_id}/report";
  }

  pub mod reports {
    const R_FILES: &str = "/api/reports/{report_id}/files";
    const R_DOWNLOAD: &str = "/api/reports/{report_id}/download";
    const R_FHASH: &str = "/api/reports/{report_id}/file_hash";
    const R_SEARCH: &str = "/api/reports/search";
    const R_G_FREQUENT_TAGS: &str = "/api/users/get-frequent-tags";
    const R_INTERESTING: &str = "/api/users/most-interesting";
  }

  pub mod files {
    const F_HASH: &str = "/api/files/{hash}";
    const F_ARCHIVE: &str = "/api/feed/archives/{publicity}/{type}/{date}";
  }

  pub mod users {
    const U_STAT: &str = "/api/users/stat";
    const U_GENERIC: &str = "/api/users/stat/generic";
    const U_MALICIOUS_IPS: &str = "/api/users/stat/malicious-ips";
    const U_IOCS: &str = "/api/users/stat/iocs";
    const U_YARA: &str = "/api/users/stat/yara";
    const U_MITRE: &str = "/api/users/stat/mitre";
  }

  pub mod intel {
    const T_G_PREVALENCE: &str = "/api/threatintel/get-prevalence";
    const T_SIMILARS: &str = "/api/threatintel/get-similars";
    const T_FEED: &str = "/api/threatintel/feed";
    const T_SIMILARITY: &str = "/api/threatintel/similarity";
    const T_DOWNLOAD_IOCS: &str = "/api/threatintel/download-iocs";
  }

  pub mod backend {
    const B_REP: &str = "/api/backend/reputation";
  }

  pub mod reputation {
    const RP_HASH: &str = "/api/reputation/hash";
    const RP_IOC_TYPE: &str = "/api/reputation/{ioc_type}";
    const RP_VOTES: &str = "/api/community/votes";
    const RP_VOTE: &str = "/api/community/vote";
  }
}

pub enum FioStats {
  Ip,
  Yara,
  Mitre,
  YaraRepo,
}

#[derive(Debug, Clone, Default)]
pub struct FileScanIO {
  pub debug: bool,
  pub raw_json: bool,
  pub api_key: String,
}

impl FileScanIO {
  pub fn api_query_report() -> () {

  }

  pub fn api_query_file() -> () {

  }

  pub fn api_scan_file() -> () {

  }

  pub fn api_scan_url() -> () {

  }

  pub fn api_download_report() -> () {

  }

  pub fn get_stats() -> () {

  }
}