use serde::Deserialize;

pub mod errors {
  use serde::Deserialize;
  
  // Struct used in response to error 400
  #[derive(Debug, Clone, Default, Deserialize)]
  pub struct FsBadRequest {
    #[serde(flatten)]
    pub detail: Option<String>,
  }

  // Struct used in response to error 422
  #[derive(Debug, Clone, Default, Deserialize)]
  pub struct FsValdiationError {
    #[serde(flatten)]
    pub detail: Option<Vec<FsValidationDetail>>,
  }

  #[derive(Debug, Clone, Default, Deserialize)]
  pub struct FsValidationDetail {
    pub ioc:      Option<Vec<String>>,
    pub msg:          Option<String>,
    #[serde(rename = "type")]
    pub _type:        Option<String>,
  }
}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct FsItems {
  pub items:                Option<Vec<FsSearchItem>>,
  pub count:                Option<usize>,
  pub count_search_params:  Option<usize>,
  pub method:               Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsSearchItem {
  pub id:             Option<String>,
  pub file:           Option<FsFile>,
  pub scan_init:      Option<FsScanInit>,
  pub state:          Option<String>,
  pub verdict:        Option<String>,
  pub tags:           Option<Vec<FsReportTags>>,
  pub date:           Option<String>,
  pub matches:        Option<Vec<FsBindMatches>>,
  pub updated_date:   Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsReportTags {
  pub source:             Option<String>,
  #[serde(rename = "sourceIdentifier")]
  pub source_identifier:  Option<String>,
  #[serde(rename = "isRootTag")]
  pub is_root_tag:        Option<bool>,
  pub tag:                Option<FsTag>,

}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsBindMatches {
  pub origin: FsMatchOrigin,
  pub matches: FsInMatches,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsInMatches {
  pub sha256: Option<Vec<Sha256Values>>
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Sha256Values {
  pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsMatchOrigin {
  pub sha256:                     Option<String>,
  #[serde(rename = "filetype")]
  pub file_type:                  Option<String>,
  pub mime_type:                  Option<String>,
  pub relation:                   Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsTag {
  pub name:                 Option<String>,
  #[serde(flatten)]
  pub synonyms:             Option<Vec<String>>,
  #[serde(flatten)]
  pub descriptions:         Option<Vec<String>>,
  pub verdict:              Option<FsVerdict>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FsVerdict {
  pub verdict:            Option<String>,
  #[serde(rename = "threatLevel")]
  pub threat_level:       Option<f32>,
  pub confidence:         Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FsFile {
  pub name:           Option<String>,
  pub mime_type:      Option<String>,
  pub long_type:      Option<String>,
  pub sha256:         Option<String>,
  pub link:           Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FsScanInit {
  pub id: String,
}








