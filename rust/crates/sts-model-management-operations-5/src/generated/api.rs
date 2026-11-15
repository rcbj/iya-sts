// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// The recovery-code mechanism's settings, and what a code is
pub mod get_backup_codes_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/backup-codes";
    pub const OPERATION_ID: &str = "getBackupCodesSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LinksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Status {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<f64>,
        #[serde(rename = "groupSize", default, skip_serializing_if = "Option::is_none")]
        pub group_size: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alphabet: Option<String>,
        #[serde(rename = "alphabetSize", default, skip_serializing_if = "Option::is_none")]
        pub alphabet_size: Option<f64>,
        #[serde(rename = "bitsPerCode", default, skip_serializing_if = "Option::is_none")]
        pub bits_per_code: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub comparison: Option<String>,
        #[serde(rename = "atRest", default, skip_serializing_if = "Option::is_none")]
        pub at_rest: Option<String>,
        #[serde(rename = "comparisonOfAHash", default, skip_serializing_if = "Option::is_none")]
        pub comparison_of_a_hash: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<Answer200LinksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue>,
        #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
        pub lead_html: Option<String>,
        #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
        pub also_html: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Answer200Status>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Where the realm's people signed in from
pub mod get_geolocation {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/geolocation";
    pub const OPERATION_ID: &str = "getGeolocation";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryWindow {
        #[serde(rename = "live")]
        Live,
        #[serde(rename = "24h")]
        V24h,
        #[serde(rename = "7d")]
        V7d,
        #[serde(rename = "30d")]
        V30d,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryContinent {
        #[serde(rename = "africa")]
        Africa,
        #[serde(rename = "antarctica")]
        Antarctica,
        #[serde(rename = "asia")]
        Asia,
        #[serde(rename = "europe")]
        Europe,
        #[serde(rename = "north-america")]
        NorthAmerica,
        #[serde(rename = "oceania")]
        Oceania,
        #[serde(rename = "south-america")]
        SouthAmerica,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<QueryWindow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continent: Option<QueryContinent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Continent {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Country {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Total {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200World {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ContinentsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CountriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso: Option<String>,
        #[serde(rename = "onMap", default, skip_serializing_if = "Option::is_none")]
        pub on_map: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub continent: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Unknown {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CitiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subdivision: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub latitude: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub longitude: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<f64>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none")]
        pub sign_ins: Option<f64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CountryOnly {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub people: Option<Option<f64>>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sign_ins: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suppressed: Option<bool>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Hidden {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cities: Option<f64>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none")]
        pub sign_ins: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DatasetsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dataset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Outlines {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub upstream: Option<String>,
        #[serde(rename = "generatedBy", default, skip_serializing_if = "Option::is_none")]
        pub generated_by: Option<String>,
        #[serde(rename = "inputSha256", default, skip_serializing_if = "Option::is_none")]
        pub input_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub license: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DrawingPicture {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DrawingLegendItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub colour: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub to: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DrawingMapLabelsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lon: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lat: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DrawingMapCitiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lon: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lat: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    /// The map as data, which the console projects and draws over Natural Earth's
    /// outlines (`/admin/geo-outlines.json`) with the code that draws `picture`
    /// here (#444): the level, the continent's slug or the country's code, each
    /// counted country's step on the scale and what it says, the labels and the
    /// cities, each where it is.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DrawingMap {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iso: Option<String>,
        /// Each counted country by ISO 3166-1 code: its step on the scale (1 to 5)
        /// and its tooltip.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub areas: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub labels: Option<Vec<Answer200DrawingMapLabelsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cities: Option<Vec<Answer200DrawingMapCitiesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub picture: Option<Answer200DrawingPicture>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub legend: Option<Vec<Answer200DrawingLegendItem>>,
        /// The map as data, which the console projects and draws over Natural
        /// Earth's outlines (`/admin/geo-outlines.json`) with the code that draws
        /// `picture` here (#444): the level, the continent's slug or the country's
        /// code, each counted country's step on the scale and what it says, the
        /// labels and the cities, each where it is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub map: Option<Answer200DrawingMap>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub windows: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continent: Option<Answer200Continent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<Answer200Country>,
        #[serde(rename = "minimumCount", default, skip_serializing_if = "Option::is_none")]
        pub minimum_count: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<f64>,
        #[serde(rename = "liveSessions", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub live_sessions: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<Answer200Total>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub world: Option<Answer200World>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub continents: Option<Vec<Answer200ContinentsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub countries: Option<Vec<Answer200CountriesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unknown: Option<Answer200Unknown>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cities: Option<Vec<Answer200CitiesItem>>,
        #[serde(rename = "countryOnly", default, skip_serializing_if = "Option::is_none")]
        pub country_only: Option<Answer200CountryOnly>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hidden: Option<Answer200Hidden>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub datasets: Option<Vec<Answer200DatasetsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributions: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesDataset>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outlines: Option<Answer200Outlines>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(rename = "noDataColour", default, skip_serializing_if = "Option::is_none")]
        pub no_data_colour: Option<String>,
    }
}

/// The policies this realm holds a credential to
pub mod get_policies {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/policies";
    pub const OPERATION_ID: &str = "getPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<String>,
        #[serde(rename = "clientsPage", default, skip_serializing_if = "Option::is_none")]
        pub clients_page: Option<i64>,
        #[serde(rename = "clientsPer", default, skip_serializing_if = "Option::is_none")]
        pub clients_per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KindsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub container: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub governs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tabbed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stored: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inherited: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problems: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasswordGenerator {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub module: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pools: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub excluded: Option<Vec<String>>,
        #[serde(rename = "drawsUntil", default, skip_serializing_if = "Option::is_none")]
        pub draws_until: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasswordDoorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Password {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_4::WithNamePrecedenceStored>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generator: Option<Answer200PasswordGenerator>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<Answer200PasswordDoorsItem>>,
        #[serde(rename = "notDoors", default, skip_serializing_if = "Option::is_none")]
        pub not_doors: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthnMail {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthnMechanismsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub primary: Option<Option<bool>>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub second_factor: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthnVocabulary {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanisms: Option<Vec<String>>,
        #[serde(rename = "secondFactors", default, skip_serializing_if = "Option::is_none")]
        pub second_factors: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_1::AuthenticationPolicyRow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inherited: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mail: Option<Answer200AuthnMail>,
        #[serde(rename = "nistWarning", default, skip_serializing_if = "Option::is_none")]
        pub nist_warning: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanisms: Option<Vec<Answer200AuthnMechanismsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vocabulary: Option<Answer200AuthnVocabulary>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServiceAccount {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_3::ServiceAccountPolicyRow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasskeyClientsRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub learned: Option<bool>,
        #[serde(rename = "learnedAt", default, skip_serializing_if = "Option::is_none")]
        pub learned_at: Option<String>,
        #[serde(rename = "learnedFailures", default, skip_serializing_if = "Option::is_none")]
        pub learned_failures: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<i64>,
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
        pub first_at: Option<String>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasskeyClientsPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasskeyClientsActions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clear: Option<String>,
        #[serde(rename = "clearAll", default, skip_serializing_if = "Option::is_none")]
        pub clear_all: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasskeyClients {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub learning: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threshold: Option<i64>,
        #[serde(rename = "windowHours", default, skip_serializing_if = "Option::is_none")]
        pub window_hours: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bound: Option<i64>,
        #[serde(rename = "learnedCount", default, skip_serializing_if = "Option::is_none")]
        pub learned_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200PasskeyClientsRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200PasskeyClientsPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Answer200PasskeyClientsActions>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_2::PasskeyPolicyRow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<Answer200PasskeyClients>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Locale {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_4::WithNamePrecedenceStored6>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesCatalogueItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locked: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesCustomItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub syntax: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(rename = "portalVisible", default, skip_serializing_if = "Option::is_none")]
        pub portal_visible: Option<bool>,
        #[serde(rename = "portalEditable", default, skip_serializing_if = "Option::is_none")]
        pub portal_editable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesSyntaxesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesActions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub define: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub update: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remove: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Attributes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_4::WithNamePrecedenceStored7>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(rename = "alwaysRequired", default, skip_serializing_if = "Option::is_none")]
        pub always_required: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogue: Option<Vec<Answer200AttributesCatalogueItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<Vec<Answer200AttributesCustomItem>>,
        #[serde(rename = "maxCustom", default, skip_serializing_if = "Option::is_none")]
        pub max_custom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub syntaxes: Option<Vec<Answer200AttributesSyntaxesItem>>,
        #[serde(rename = "missingFilter", default, skip_serializing_if = "Option::is_none")]
        pub missing_filter: Option<String>,
        #[serde(rename = "missingAsked", default, skip_serializing_if = "Option::is_none")]
        pub missing_asked: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub missing: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Answer200AttributesActions>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PostLogin {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_3::PostLoginPolicyRow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithContainerDefinitionContainerObjectClasses2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub references: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<sts_model_management_components_4::WithNamePrecedenceStored2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<Answer200KindsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforcement: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<Answer200Password>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<Answer200Authn>,
        #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
        pub service_account: Option<Answer200ServiceAccount>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<Answer200Locale>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Answer200Attributes>,
        #[serde(rename = "postLogin", default, skip_serializing_if = "Option::is_none")]
        pub post_login: Option<Answer200PostLogin>,
    }
}

/// Offer ML-DSA again to one learned client
pub mod clear_passkey_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/clear-passkey-client";
    pub const OPERATION_ID: &str = "clearPasskeyClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The learned client, as listed.
        pub client: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors147;
}

/// Offer ML-DSA again to every learned client
pub mod clear_passkey_clients {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/clear-passkey-clients";
    pub const OPERATION_ID: &str = "clearPasskeyClients";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors147;
}

/// Define a custom attribute in this realm
pub mod define_person_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/define-person-attribute";
    pub const OPERATION_ID: &str = "definePersonAttribute";

    /// What its values are checked against. Default `string`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySyntax {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "integer")]
        Integer,
        #[serde(rename = "boolean")]
        Boolean,
        #[serde(rename = "date")]
        Date,
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "uri")]
        Uri,
        #[serde(rename = "dn")]
        Dn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The attribute's name.
        pub name: String,
        /// What the pages draw beside the name.
        pub label: String,
        /// What its values are checked against. Default `string`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub syntax: Option<BodySyntax>,
        /// Whether it holds several values (`true`, or `multiple` from a form).
        /// Default false.
        #[serde(rename = "multiValued", default, skip_serializing_if = "Option::is_none")]
        pub multi_valued: Option<sts_model_base::unions::BoolOrString>,
        /// What it is for. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Whether a person sees their own values on the user portal's Overview
        /// (#700). Default false.
        #[serde(rename = "portalVisible", default, skip_serializing_if = "Option::is_none")]
        pub portal_visible: Option<bool>,
        /// Whether a person may change their own values there (`POST
        /// /account-api/attributes`). Implies `portalVisible`, which is stored true
        /// with it. Default false.
        #[serde(rename = "portalEditable", default, skip_serializing_if = "Option::is_none")]
        pub portal_editable: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors150;
}

/// Delete a named authentication policy
pub mod delete_named_authn_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/delete-named-authn-policy";
    pub const OPERATION_ID: &str = "deleteNamedAuthnPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors144;
}

/// Remove a custom attribute of this realm
pub mod remove_person_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/remove-person-attribute";
    pub const OPERATION_ID: &str = "removePersonAttribute";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The attribute's name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors150;
}

/// Remove this realm's attribute policy profile
pub mod reset_attributes_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-attributes-policy";
    pub const OPERATION_ID: &str = "resetAttributesPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors149;
}

/// Remove this realm's authentication policy profile
pub mod reset_authn_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-authn-policy";
    pub const OPERATION_ID: &str = "resetAuthnPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile. Only `default` exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors143;
}

/// Remove this realm's locale policy profile
pub mod reset_locale_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-locale-policy";
    pub const OPERATION_ID: &str = "resetLocalePolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors148;
}

/// Remove this realm's passkey policy profile
pub mod reset_passkey_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-passkey-policy";
    pub const OPERATION_ID: &str = "resetPasskeyPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors146;
}

/// Remove this realm's password policy profile
pub mod reset_password_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-password-policy";
    pub const OPERATION_ID: &str = "resetPasswordPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors142;
}

/// Remove this realm's post-login activity policy profile
pub mod reset_post_login_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-postLogin-policy";
    pub const OPERATION_ID: &str = "resetPostLoginPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors151;
}

/// Remove this realm's service-account policy profile
pub mod reset_service_account_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/reset-serviceAccount-policy";
    pub const OPERATION_ID: &str = "resetServiceAccountPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default` goes back to inheriting; a named one is
        /// removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors145;
}

/// Set the attribute policy profile
pub mod save_attributes_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-attributes-policy";
    pub const OPERATION_ID: &str = "saveAttributesPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRequiredAttributes {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// The attributes every person in this realm must hold a value of, besides
        /// uid, cn and sn, which are always required. A list, or comma-separated.
        /// Any attribute a person may be given a value for: the inetOrgPerson
        /// schema, the credential catalogue, mail, and this realm's custom
        /// attributes. Enforced in product mode: a create without one is refused at
        /// every door, and an edit may not take one away. Default givenName, sn and
        /// mail. Default `givenName, sn, mail`.
        #[serde(rename = "requiredAttributes")]
        pub required_attributes: BodyRequiredAttributes,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors149;
}

/// Set the authentication policy profile
pub mod save_authn_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-authn-policy";
    pub const OPERATION_ID: &str = "saveAuthnPolicy";

    /// `if-held`: a person is asked for a second factor when they hold one (or
    /// their entry says stsMfaRequired). `always`: everybody in this realm is, and
    /// somebody who holds none is sent to enrol one at their next sign-in. This
    /// replaced authn.mfaRequired. There is no "never": a held factor is always
    /// asked for. Default `if-held`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRequireSecondFactor {
        #[serde(rename = "if-held")]
        IfHeld,
        #[serde(rename = "always")]
        Always,
    }

    /// For anybody holding a console role (Admin Read or Admin Write) who holds no
    /// second factor. `offer`: they are shown the step that sets one up, with an
    /// Ignore button, at every sign-in. `always`: they must set one up before they
    /// are signed in — except the default realm's built-in administrator
    /// (admin.bootstrapUsername), who is only ever offered one, so a service is
    /// never left with nobody who can sign in. `if-held`: as everybody else, by the
    /// field above. WEAKER THAN `always`: an administrator on a password alone is
    /// an administrator anyone with the password is. Default `offer`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRequireSecondFactorForAdministrators {
        #[serde(rename = "if-held")]
        IfHeld,
        #[serde(rename = "offer")]
        Offer,
        #[serde(rename = "always")]
        Always,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile. Only `default` exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// `if-held`: a person is asked for a second factor when they hold one (or
        /// their entry says stsMfaRequired). `always`: everybody in this realm is,
        /// and somebody who holds none is sent to enrol one at their next sign-in.
        /// This replaced authn.mfaRequired. There is no "never": a held factor is
        /// always asked for. Default `if-held`.
        #[serde(rename = "requireSecondFactor")]
        pub require_second_factor: BodyRequireSecondFactor,
        /// For anybody holding a console role (Admin Read or Admin Write) who holds
        /// no second factor. `offer`: they are shown the step that sets one up,
        /// with an Ignore button, at every sign-in. `always`: they must set one up
        /// before they are signed in — except the default realm's built-in
        /// administrator (admin.bootstrapUsername), who is only ever offered one,
        /// so a service is never left with nobody who can sign in. `if-held`: as
        /// everybody else, by the field above. WEAKER THAN `always`: an
        /// administrator on a password alone is an administrator anyone with the
        /// password is. Default `offer`.
        #[serde(rename = "requireSecondFactorForAdministrators")]
        pub require_second_factor_for_administrators: BodyRequireSecondFactorForAdministrators,
        /// A password on the sign-in screen. As a SECOND factor it is the password
        /// asked for after a wallet or other passwordless first factor.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "passwordPrimary")]
        pub password_primary: sts_model_base::unions::BoolOrString,
        /// A password on the sign-in screen. As a SECOND factor it is the password
        /// asked for after a wallet or other passwordless first factor.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "passwordSecondFactor")]
        pub password_second_factor: sts_model_base::unions::BoolOrString,
        /// Any passkey (WebAuthn credential) the person holds, signing them in with
        /// no password. A passkey has no role: this row says, at each sign-in,
        /// whether any of them may be a first factor in this realm, unless the
        /// first factors of the authentication policy an application names
        /// (appAuthnPolicy) say otherwise. (`true`/`false`, or `TRUE`/`FALSE` from
        /// a form.) Default true.
        #[serde(rename = "passkeyPrimary")]
        pub passkey_primary: sts_model_base::unions::BoolOrString,
        /// Any passkey (WebAuthn credential) the person holds, asked for after a
        /// first factor. A passkey has no role: this row says, at each sign-in,
        /// whether any of them may be a second factor in this realm, unless the
        /// second factors of the authentication policy an application names
        /// (appAuthnPolicy) say otherwise. (`true`/`false`, or `TRUE`/`FALSE` from
        /// a form.) Default true.
        #[serde(rename = "securityKeySecondFactor")]
        pub security_key_second_factor: sts_model_base::unions::BoolOrString,
        /// An RFC 6238 one-time code. Never a first factor: this service holds the
        /// same shared secret the app does. Off here, nobody may ENROL one; a
        /// person who already holds one is still asked for it, because an off
        /// switch that downgraded every enrolled account to a password alone would
        /// do something other than it says (this row replaced totp.enabled, and
        /// keeps its contract). (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default true.
        #[serde(rename = "totpSecondFactor")]
        pub totp_second_factor: sts_model_base::unions::BoolOrString,
        /// A single-use code from a set the person generated. Off here, no new set
        /// may be generated; a set already held still works (this row replaced
        /// backupCodes.enabled, and keeps its contract). (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "recoveryCodeSecondFactor")]
        pub recovery_code_second_factor: sts_model_base::unions::BoolOrString,
        /// A six-digit code mailed to the person's VERIFIED address. NIST SP
        /// 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used for out-of-band
        /// authentication", because a mailbox may be reached with a password alone,
        /// and mail may be read in transit or rerouted. Off by default for that
        /// reason; turn it on only where that is an accepted risk. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "emailCodePrimary")]
        pub email_code_primary: sts_model_base::unions::BoolOrString,
        /// A six-digit code mailed to the person's VERIFIED address. NIST SP
        /// 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used for out-of-band
        /// authentication", because a mailbox may be reached with a password alone,
        /// and mail may be read in transit or rerouted. Off by default for that
        /// reason; turn it on only where that is an accepted risk. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "emailCodeSecondFactor")]
        pub email_code_second_factor: sts_model_base::unions::BoolOrString,
        /// A single-use link mailed to the person's VERIFIED address, which
        /// completes the sign-in only in the browser that started it. NIST SP
        /// 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used for out-of-band
        /// authentication", because a mailbox may be reached with a password alone,
        /// and mail may be read in transit or rerouted. Off by default for that
        /// reason; turn it on only where that is an accepted risk. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "emailLinkPrimary")]
        pub email_link_primary: sts_model_base::unions::BoolOrString,
        /// A single-use link mailed to the person's VERIFIED address, which
        /// completes the sign-in only in the browser that started it. NIST SP
        /// 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used for out-of-band
        /// authentication", because a mailbox may be reached with a password alone,
        /// and mail may be read in transit or rerouted. Off by default for that
        /// reason; turn it on only where that is an accepted risk. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "emailLinkSecondFactor")]
        pub email_link_second_factor: sts_model_base::unions::BoolOrString,
        /// A verified TLS client certificate: GET /tls/sign-in, or Continue with
        /// your certificate on the sign-in screen. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "certificatePrimary")]
        pub certificate_primary: sts_model_base::unions::BoolOrString,
        /// GET /authn/spnego with a Kerberos ticket. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "kerberosPrimary")]
        pub kerberos_primary: sts_model_base::unions::BoolOrString,
        /// /authn/wallet with a credential this realm issued, or a SIOPv2
        /// self-issued ID Token from an enrolled key. As a SECOND factor, the
        /// wallet presented after a password. (`true`/`false`, or `TRUE`/`FALSE`
        /// from a form.) Default true.
        #[serde(rename = "walletPrimary")]
        pub wallet_primary: sts_model_base::unions::BoolOrString,
        /// /authn/wallet with a credential this realm issued, or a SIOPv2
        /// self-issued ID Token from an enrolled key. As a SECOND factor, the
        /// wallet presented after a password. (`true`/`false`, or `TRUE`/`FALSE`
        /// from a form.) Default true.
        #[serde(rename = "walletSecondFactor")]
        pub wallet_second_factor: sts_model_base::unions::BoolOrString,
        /// A sign-in asserted by a configured federation partner. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "federationPrimary")]
        pub federation_primary: sts_model_base::unions::BoolOrString,
        /// From the moment it is sent. At most ten minutes, NIST SP 800-63B-4
        /// section 3.1.3.2's bound for an out-of-band secret. Between 60 and 600.
        /// Default 300.
        #[serde(rename = "emailCodeTtlS")]
        pub email_code_ttl_s: sts_model_base::unions::IntegerOrString,
        /// How many wrong codes one sign-in step accepts before it is ended and the
        /// person starts again. The per-person and per-network rate limits apply as
        /// well. Between 1 and 10. Default 5.
        #[serde(rename = "emailCodeAttempts")]
        pub email_code_attempts: sts_model_base::unions::IntegerOrString,
        /// A new code or link replaces the last one, which stops working. At most
        /// three are sent for one sign-in step. Between 15 and 600. Default 60.
        #[serde(rename = "emailResendS")]
        pub email_resend_s: sts_model_base::unions::IntegerOrString,
        /// NIST SP 800-63B-4 section 3.2.2 asks for no more than 100. The person,
        /// and their administrators, are told, and the person turns it on again
        /// from the portal. Between 5 and 100. Default 100.
        #[serde(rename = "emailFailureLimit")]
        pub email_failure_limit: sts_model_base::unions::IntegerOrString,
        /// OFF BY DEFAULT. On, a person signing in on a browser they chose to
        /// remember is not asked for their second factor again within the period
        /// below of last giving it on that browser. NEVER at the admin console, the
        /// user portal or the protocol debugger; never for an administrator; never
        /// while the sign-in's risk is medium or higher; and the sign-in is then
        /// ONE factor to every relying party — amr ["pwd"] and acr "1", as a
        /// password alone — so an application asking for "mfa" is refused it. The
        /// browser is recognised by a bearer cookie: whoever copies the cookie
        /// skips the second factor too, until the copy is caught. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "rememberedBrowserSkipsSecondFactor")]
        pub remembered_browser_skips_second_factor: sts_model_base::unions::BoolOrString,
        /// Counted from the last time the person gave their second factor on that
        /// browser. After it they are asked again, and giving it starts the period
        /// again. Between 1 and 400. Default 30.
        #[serde(rename = "rememberedBrowserDays")]
        pub remembered_browser_days: sts_model_base::unions::IntegerOrString,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors143;
}

/// Set the locale policy profile
pub mod save_locale_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-locale-policy";
    pub const OPERATION_ID: &str = "saveLocalePolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// A BCP 47 language tag (RFC 5646), such as en, fr-CA or zh-TW. Pages are
        /// drawn in it when the request, the person's preferredLanguage, the
        /// language chooser and the browser name nothing a catalog answers; dates
        /// and numbers are formatted for it even where no catalog does. Mail to a
        /// person whose entry names no language is written in it. Replaces the
        /// setting mail.defaultLanguage. Default `en`.
        #[serde(rename = "defaultLocale")]
        pub default_locale: String,
        /// ON BY DEFAULT. A person entry created in this realm without a
        /// preferredLanguage (RFC 2798 section 2.7) is given the default language
        /// above as one — by the console, the management API, SCIM, a federated or
        /// self-service sign-up, or a bulk load. A named profile applies where the
        /// application that caused the creation names it, or one of the person's
        /// groups does. Existing entries are never rewritten. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "populatePreferredLanguage")]
        pub populate_preferred_language: sts_model_base::unions::BoolOrString,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors148;
}

/// Create or replace a named authentication policy in this realm
pub mod save_named_authn_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-named-authn-policy";
    pub const OPERATION_ID: &str = "saveNamedAuthnPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's name.
        pub name: String,
        /// What the policy is for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Where several named policies are named for one sign-in, the lowest
        /// applies; 100 when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// The first-factor mechanisms allowed: password, password-mfa, webauthn,
        /// spnego, wallet, federation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanisms: Option<Vec<String>>,
        /// The second factors allowed: password, securityKey, totp, recoveryCode,
        /// emailCode, emailLink, wallet.
        #[serde(rename = "secondFactors", default, skip_serializing_if = "Option::is_none")]
        pub second_factors: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors144;
}

/// Set the passkey policy profile
pub mod save_passkey_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-passkey-policy";
    pub const OPERATION_ID: &str = "savePasskeyPolicy";

    /// The `residentKey` an enrolment through *Use a security key* (or one that
    /// names no kind) sends WHILE usernameless sign-in is ON. While it is off the
    /// button always asks `required`, so it makes a discoverable credential as
    /// *Create a passkey* does (which asks `required` always). `discouraged` or
    /// `preferred` spare a security key's few resident slots, at the cost of a key
    /// that needs the username to sign in. Replaces the setting
    /// webauthn.residentKey. Default `required`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySecurityKeyResidentKey {
        #[serde(rename = "discouraged")]
        Discouraged,
        #[serde(rename = "preferred")]
        Preferred,
        #[serde(rename = "required")]
        Required,
    }

    /// `allow` (the default) accepts any passkey. `disallow` accepts only
    /// DEVICE-BOUND ones: a passkey whose authenticator says it may be backed up or
    /// synced (the BE flag, WebAuthn Level 3 section 6.1) is refused when it is
    /// registered and when it signs somebody in, so a synced passkey enrolled
    /// before the realm said no stops working too. BE never changes for a
    /// credential. Default `allow`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyBackupEligibility {
        #[serde(rename = "allow")]
        Allow,
        #[serde(rename = "disallow")]
        Disallow,
    }

    /// `off` (the default) accepts a passkey whatever its signature algorithm.
    /// `sign-in` accepts only a POST-QUANTUM passkey, one whose algorithm is
    /// ML-DSA-44, ML-DSA-65 or ML-DSA-87 (RFC 9964), when it signs somebody in, as
    /// the first credential or as the second factor; a classical one may still be
    /// registered. `registration-and-sign-in` refuses a classical one at
    /// registration too, and enrolment then offers only ML-DSA. The algorithm
    /// decides, not the lane a key was created in. Refused while the realm offers
    /// no ML-DSA (webauthn.algorithms names none, and neither webauthn.pqcOnly nor
    /// webauthn.pqcAlongsideClassical is on). Default `off`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPostQuantumRequired {
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "sign-in")]
        SignIn,
        #[serde(rename = "registration-and-sign-in")]
        RegistrationAndSignIn,
    }

    /// `realm` (the default) follows the realm's
    /// webauthn.postQuantumAllowCredentials. Read only while postQuantumRequired
    /// requires a post-quantum passkey at sign-in. `narrow` names only the person's
    /// post-quantum (ML-DSA) passkeys in the passkey step's request, so a classical
    /// one is never offered, and a person whose device holds only their classical
    /// one sees the platform's own "no passkey found" message. `list-and-refuse`
    /// names every passkey they hold and refuses a classical one after the
    /// ceremony, with a page saying that this application requires a post-quantum
    /// passkey and where to add one; the person may then pick a passkey that will
    /// be refused. A person holding no post-quantum passkey is told before any
    /// ceremony either way. Left out of a save, `realm` is kept. Default `realm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPostQuantumAllowCredentials {
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "narrow")]
        Narrow,
        #[serde(rename = "list-and-refuse")]
        ListAndRefuse,
    }

    /// `realm` (the default) follows webauthn.pqcOnly and
    /// webauthn.pqcAlongsideClassical. `pq-only` offers only ML-DSA, and refuses a
    /// retry with the classical algorithms. `pq-first` offers ML-DSA first and the
    /// classical algorithms after it, even where the realm requests ML-DSA only.
    /// `classical-only` offers no ML-DSA and no post-quantum passkey beside a
    /// classical one, for people whose devices fail an ML-DSA registration. Refused
    /// with postQuantumRequired other than off or with attestationAlgorithms set
    /// (classical-only), and where the algorithms offered name no ML-DSA (pq-only,
    /// pq-first). Left out of a save, `realm` is kept. Default `realm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRegistrationMode {
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "pq-only")]
        PqOnly,
        #[serde(rename = "pq-first")]
        PqFirst,
        #[serde(rename = "classical-only")]
        ClassicalOnly,
    }

    /// `realm` (the default) follows webauthn.pqcAlongsideClassical. `both` gives
    /// this profile's people a classical and a post-quantum passkey side by side,
    /// each under its own user handle, wherever the realm's setting is off; `one`
    /// gives them one lane wherever it is on. webauthn.pqcOnly still means one
    /// lane. Refused as `both` with registrationMode classical-only. Left out of a
    /// save, `realm` is kept. Default `realm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyLanes {
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "both")]
        Both,
        #[serde(rename = "one")]
        One,
    }

    /// `none` (the default) shows webauthn.rpName alone. `realm`, `organisation` or
    /// `realm-and-organisation` append the realm's name and/or
    /// saml.organizationName, so a person with accounts in several realms can tell
    /// the prompts apart. Default `none`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRpNameExtras {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "organisation")]
        Organisation,
        #[serde(rename = "realm-and-organisation")]
        RealmAndOrganisation,
    }

    /// `any` BY DEFAULT IN DEVELOPMENT, `not-weaker` IN PRODUCT. Whether a way back
    /// into the account that asks for no passkey — a password reset link, an
    /// activation link, a recovery code, an emailed code or link — restores access
    /// for a person who holds one. `any`: at once. `not-weaker`: the first sign-in
    /// after it that is not a passkey sign-in reaches no application; the person
    /// registers a passkey that satisfies this policy and signs in with it.
    /// `operator-only`: as not-weaker, and the self-service doors (the
    /// forgot-password form, a recovery code or an emailed code or link at sign-in)
    /// are refused; only an administrator's reset link, generated password or
    /// activation link remains. Left out of a save, the built-in default is kept.
    /// Default `any`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRecoveryAssurance {
        #[serde(rename = "any")]
        Any,
        #[serde(rename = "not-weaker")]
        NotWeaker,
        #[serde(rename = "operator-only")]
        OperatorOnly,
    }

    /// `off` BY DEFAULT. `on` lets an administrator holding the Admin Write console
    /// role enrol a passkey for a person this profile applies to, from the person's
    /// page on the console or /admin-api: the registration ceremony runs in the
    /// administrator's own browser, against an authenticator they hold (a security
    /// key to be handed over, say), under the person's user handle, and is verified
    /// exactly as the person's own registration is — attestation, algorithms and
    /// this policy's registration rules. Nothing made elsewhere can be imported.
    /// The key records which administrator enrolled it and when, and the person is
    /// told. Left out of a save, the built-in default is kept. Default `off`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAdminEnrolment {
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "on")]
        On,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// ON BY DEFAULT. On, the sign-in screen offers *Sign in with a passkey*
        /// and the username field's autofill, which ask the browser for any
        /// discoverable credential of this realm (WebAuthn Level 3 section 5.4,
        /// `allowCredentials` empty) and sign in the account its user handle names,
        /// with user verification required and checked. Off, neither is offered and
        /// a sign-in always names the person first. Replaces the setting
        /// webauthn.usernameless. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default true.
        #[serde(rename = "allowUsernameless")]
        pub allow_usernameless: sts_model_base::unions::BoolOrString,
        /// OFF BY DEFAULT. On, an application whose authentication mechanism is a
        /// passkey and nothing else (the authentication policy it names,
        /// appAuthnPolicy, lists `webauthn` alone) gets a sign-in screen with no
        /// username field: *Sign in with a passkey* is the way in, and a sign-in
        /// that names a person is refused. It needs the row above. The realm's
        /// `default` profile does not apply it to the admin console, the debugger
        /// or the user portal; a named profile selecting that application does.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "requireUsernameless")]
        pub require_usernameless: sts_model_base::unions::BoolOrString,
        /// The `residentKey` an enrolment through *Use a security key* (or one that
        /// names no kind) sends WHILE usernameless sign-in is ON. While it is off
        /// the button always asks `required`, so it makes a discoverable credential
        /// as *Create a passkey* does (which asks `required` always). `discouraged`
        /// or `preferred` spare a security key's few resident slots, at the cost of
        /// a key that needs the username to sign in. Replaces the setting
        /// webauthn.residentKey. Default `required`.
        #[serde(rename = "securityKeyResidentKey")]
        pub security_key_resident_key: BodySecurityKeyResidentKey,
        /// `allow` (the default) accepts any passkey. `disallow` accepts only
        /// DEVICE-BOUND ones: a passkey whose authenticator says it may be backed
        /// up or synced (the BE flag, WebAuthn Level 3 section 6.1) is refused when
        /// it is registered and when it signs somebody in, so a synced passkey
        /// enrolled before the realm said no stops working too. BE never changes
        /// for a credential. Default `allow`.
        #[serde(rename = "backupEligibility")]
        pub backup_eligibility: BodyBackupEligibility,
        /// OFF BY DEFAULT. On, registration asks the authenticator for its minimum
        /// PIN length (CTAP 2.1 section 12.4, the minPinLength extension), records
        /// it on the key, and refuses a key whose minimum is below the next row, at
        /// registration and at every sign-in. A key answers only for relying
        /// parties it was configured to tell (CTAP 2.1 setMinPINLength with this RP
        /// ID); every other key, and every platform or synced passkey, does not
        /// report, and is refused unless the row after next is on. (`true`/`false`,
        /// or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "enforcePinLength")]
        pub enforce_pin_length: sts_model_base::unions::BoolOrString,
        /// The shortest PIN a security key may be set to accept, as the key itself
        /// reports it, while the row above is on. Between 4 (CTAP 2.1's own floor)
        /// and 63. Between 4 and 63. Default 4.
        #[serde(rename = "minPinLength")]
        pub min_pin_length: sts_model_base::unions::IntegerOrString,
        /// OFF BY DEFAULT, which is the strict reading: while the PIN length is
        /// enforced, a key that does not report it is refused. On, such a key is
        /// accepted and only a reported minimum is held to the rule — so the rule
        /// then binds only keys configured to report to this relying party.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "pinLengthOnlyIfSupported")]
        pub pin_length_only_if_supported: sts_model_base::unions::BoolOrString,
        /// OFF BY DEFAULT. The attestation rules (the webauthn.attestation*
        /// settings: the policy, the AAGUID list, the certification level and FIPS)
        /// are checked when a passkey is registered. On, they are checked again at
        /// every sign-in against what was recorded then and the FIDO Metadata
        /// Service as it is now, so a key registered before a rule was tightened,
        /// or whose model was since reported compromised, stops signing anybody in.
        /// A key with no trusted attestation fails every rule that demands one.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "enforceAttestationAtSignIn")]
        pub enforce_attestation_at_sign_in: sts_model_base::unions::BoolOrString,
        /// `off` (the default) accepts a passkey whatever its signature algorithm.
        /// `sign-in` accepts only a POST-QUANTUM passkey, one whose algorithm is
        /// ML-DSA-44, ML-DSA-65 or ML-DSA-87 (RFC 9964), when it signs somebody in,
        /// as the first credential or as the second factor; a classical one may
        /// still be registered. `registration-and-sign-in` refuses a classical one
        /// at registration too, and enrolment then offers only ML-DSA. The
        /// algorithm decides, not the lane a key was created in. Refused while the
        /// realm offers no ML-DSA (webauthn.algorithms names none, and neither
        /// webauthn.pqcOnly nor webauthn.pqcAlongsideClassical is on). Default
        /// `off`.
        #[serde(rename = "postQuantumRequired")]
        pub post_quantum_required: BodyPostQuantumRequired,
        /// `realm` (the default) follows the realm's
        /// webauthn.postQuantumAllowCredentials. Read only while
        /// postQuantumRequired requires a post-quantum passkey at sign-in. `narrow`
        /// names only the person's post-quantum (ML-DSA) passkeys in the passkey
        /// step's request, so a classical one is never offered, and a person whose
        /// device holds only their classical one sees the platform's own "no
        /// passkey found" message. `list-and-refuse` names every passkey they hold
        /// and refuses a classical one after the ceremony, with a page saying that
        /// this application requires a post-quantum passkey and where to add one;
        /// the person may then pick a passkey that will be refused. A person
        /// holding no post-quantum passkey is told before any ceremony either way.
        /// Left out of a save, `realm` is kept. Default `realm`.
        #[serde(rename = "postQuantumAllowCredentials", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_allow_credentials: Option<BodyPostQuantumAllowCredentials>,
        /// `realm` (the default) offers the realm's webauthn.algorithms. Otherwise
        /// the signature algorithms a passkey registration offers to this profile's
        /// people, in order of preference (an authenticator makes the first it
        /// supports), from the algorithms webauthn.algorithms may name. The next
        /// row may narrow or reorder it, and a passkey whose algorithm is not one
        /// this profile offers is refused when it is registered. Left out of a
        /// save, `realm` is kept. An ordered, comma-separated list of ML-DSA-87,
        /// ML-DSA-65, ML-DSA-44, EdDSA, ES256, RS256, ESP256, Ed25519, ESP384,
        /// ES384, ESP512, ES512, Ed448, ES256K, PS256, PS384, PS512, RS384, RS512,
        /// or `none`. Default `realm`.
        #[serde(rename = "registrationAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub registration_algorithms: Option<String>,
        /// `realm` (the default) follows webauthn.pqcOnly and
        /// webauthn.pqcAlongsideClassical. `pq-only` offers only ML-DSA, and
        /// refuses a retry with the classical algorithms. `pq-first` offers ML-DSA
        /// first and the classical algorithms after it, even where the realm
        /// requests ML-DSA only. `classical-only` offers no ML-DSA and no
        /// post-quantum passkey beside a classical one, for people whose devices
        /// fail an ML-DSA registration. Refused with postQuantumRequired other than
        /// off or with attestationAlgorithms set (classical-only), and where the
        /// algorithms offered name no ML-DSA (pq-only, pq-first). Left out of a
        /// save, `realm` is kept. Default `realm`.
        #[serde(rename = "registrationMode", default, skip_serializing_if = "Option::is_none")]
        pub registration_mode: Option<BodyRegistrationMode>,
        /// `realm` (the default) follows webauthn.pqcAlongsideClassical. `both`
        /// gives this profile's people a classical and a post-quantum passkey side
        /// by side, each under its own user handle, wherever the realm's setting is
        /// off; `one` gives them one lane wherever it is on. webauthn.pqcOnly still
        /// means one lane. Refused as `both` with registrationMode classical-only.
        /// Left out of a save, `realm` is kept. Default `realm`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lanes: Option<BodyLanes>,
        /// EMPTY BY DEFAULT: every client is offered the list as it stands.
        /// Otherwise up to 20 rules separated by `;`, each `<browser> on <system>`,
        /// where either side is a family as the passkey ceremony rows name it
        /// (`Chrome`, `Firefox`, `macOS`, `Android`) or `*` for any, optionally
        /// followed by a major-version range (`141`, `130-140`, `130-`, `-140`):
        /// `Firefox 140- on Linux; * on Android 13`. A passkey registration from a
        /// matching client offers the list less ML-DSA (ES256 and RS256 where that
        /// leaves none). Not applied where a classical passkey is not allowed —
        /// registrationMode pq-only, webauthn.pqcOnly, postQuantumRequired
        /// registration-and-sign-in, or at the sign-in step under
        /// postQuantumRequired sign-in — nor to the post-quantum lane, and the
        /// ceremony row says it was not. Left out of a save, empty is kept. Default
        /// empty.
        #[serde(rename = "clientRules", default, skip_serializing_if = "Option::is_none")]
        pub client_rules: Option<String>,
        /// The WebAuthn hints (Level 3 section 5.4.8) the portal's *Create a
        /// passkey* sends, in order, from security-key, client-device and hybrid,
        /// or none. They tell the browser which way of making the passkey to lead
        /// with. A hint may not contradict webauthn.authenticatorAttachment:
        /// client-device implies platform, security-key and hybrid cross-platform.
        /// An ordered, comma-separated list of security-key, client-device, hybrid,
        /// or `none`. Default `client-device,hybrid`.
        #[serde(rename = "passkeyHints")]
        pub passkey_hints: String,
        /// The hints *Use a security key* sends, in order, or none. The button asks
        /// for a cross-platform authenticator, so client-device contradicts it and
        /// is refused. An ordered, comma-separated list of security-key,
        /// client-device, hybrid, or `none`. Default `security-key`.
        #[serde(rename = "securityKeyHints")]
        pub security_key_hints: String,
        /// The hints a sign-in ceremony sends — the passkey step, the sign-in with
        /// no username and its autofill — in order, or none (the default: the
        /// browser offers every way it knows). An ordered, comma-separated list of
        /// security-key, client-device, hybrid, or `none`. Default `none`.
        #[serde(rename = "signInHints")]
        pub sign_in_hints: String,
        /// EMPTY BY DEFAULT: no serial is checked. Set to an attribute of a
        /// person's entry (for example `serialNumber`, which may hold several
        /// values), a security key registers only with a TRUSTED enterprise
        /// attestation whose certificate names a device serial that is one of that
        /// person's values. Needs webauthn.attestation set to enterprise, and the
        /// vendor or platform configured to release enterprise attestation to this
        /// RP ID; without that the browser sends ordinary attestation and every
        /// registration is refused. A directory attribute name, or empty for none.
        /// Default empty.
        #[serde(rename = "enterpriseSerialAttribute")]
        pub enterprise_serial_attribute: String,
        /// EMPTY BY DEFAULT: the name the sign-in knows, else the username.
        /// Otherwise up to six directory attributes in order, separated by commas;
        /// a group of attributes separated by spaces (givenName sn) joins their
        /// values. The first whose every attribute has a value becomes
        /// user.displayName (WebAuthn Level 3 section 5.4.3), with control and
        /// direction-changing characters removed and at most 64 characters. The
        /// username is always user.name. Default empty.
        #[serde(rename = "userDisplayName")]
        pub user_display_name: String,
        /// `none` (the default) shows webauthn.rpName alone. `realm`,
        /// `organisation` or `realm-and-organisation` append the realm's name
        /// and/or saml.organizationName, so a person with accounts in several
        /// realms can tell the prompts apart. Default `none`.
        #[serde(rename = "rpNameExtras")]
        pub rp_name_extras: BodyRpNameExtras,
        /// EMPTY BY DEFAULT: the provider's name, else "Passkey" or "Security key".
        /// Otherwise this text, with {provider} and {kind} filled in, at most 60
        /// characters. The person may rename it afterwards, as always. Default
        /// empty.
        #[serde(rename = "credentialLabel")]
        pub credential_label: String,
        /// ON BY DEFAULT: one "Use passkey" step whose request lists every one of
        /// the person's passkeys, and the browser offers whichever is present. Off,
        /// a person with more than one is shown a choice per passkey, by its name,
        /// and the request names only that one. (`true`/`false`, or `TRUE`/`FALSE`
        /// from a form.) Default true.
        #[serde(rename = "aggregateDevices")]
        pub aggregate_devices: sts_model_base::unions::BoolOrString,
        /// `any` BY DEFAULT IN DEVELOPMENT, `not-weaker` IN PRODUCT. Whether a way
        /// back into the account that asks for no passkey — a password reset link,
        /// an activation link, a recovery code, an emailed code or link — restores
        /// access for a person who holds one. `any`: at once. `not-weaker`: the
        /// first sign-in after it that is not a passkey sign-in reaches no
        /// application; the person registers a passkey that satisfies this policy
        /// and signs in with it. `operator-only`: as not-weaker, and the
        /// self-service doors (the forgot-password form, a recovery code or an
        /// emailed code or link at sign-in) are refused; only an administrator's
        /// reset link, generated password or activation link remains. Left out of a
        /// save, the built-in default is kept. Default `any`.
        #[serde(rename = "recoveryAssurance", default, skip_serializing_if = "Option::is_none")]
        pub recovery_assurance: Option<BodyRecoveryAssurance>,
        /// `none` BY DEFAULT: an attestation is accepted whatever it is signed
        /// with. Otherwise a list from post-quantum, ml-dsa-44, ml-dsa-65,
        /// ml-dsa-87, slh-dsa and composite-ml-dsa: a passkey registers only with a
        /// TRUSTED attestation that carries a certificate, whose statement
        /// signature and the signature on every certificate of its chain, from the
        /// leaf to the trust anchor, are each one the list allows (`post-quantum`
        /// allows any ML-DSA, SLH-DSA or composite ML-DSA signature). Self and none
        /// attestation are refused, having no certificate. With
        /// enforceAttestationAtSignIn on, every sign-in holds the passkey to it by
        /// what its registration recorded, so a passkey registered before the rule
        /// stops working. This is the attestation's algorithm, not the passkey's
        /// own (postQuantumRequired). Left out of a save, the built-in default is
        /// kept. An ordered, comma-separated list of post-quantum, ml-dsa-44,
        /// ml-dsa-65, ml-dsa-87, slh-dsa, composite-ml-dsa, or `none`. Default
        /// `none`.
        #[serde(rename = "attestationAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub attestation_algorithms: Option<String>,
        /// `off` BY DEFAULT. `on` lets an administrator holding the Admin Write
        /// console role enrol a passkey for a person this profile applies to, from
        /// the person's page on the console or /admin-api: the registration
        /// ceremony runs in the administrator's own browser, against an
        /// authenticator they hold (a security key to be handed over, say), under
        /// the person's user handle, and is verified exactly as the person's own
        /// registration is — attestation, algorithms and this policy's registration
        /// rules. Nothing made elsewhere can be imported. The key records which
        /// administrator enrolled it and when, and the person is told. Left out of
        /// a save, the built-in default is kept. Default `off`.
        #[serde(rename = "adminEnrolment", default, skip_serializing_if = "Option::is_none")]
        pub admin_enrolment: Option<BodyAdminEnrolment>,
        /// OFF BY DEFAULT. On, an issuance to an application this profile covers
        /// waits until the sign-on session is bound to the browser's key, and is
        /// refused when the browser skipped that registration or the wait elapsed
        /// without a binding. A session that was never offered registration is not
        /// refused by this row. Refused while authn.deviceBoundSessions is off.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "deviceBoundRequired", default, skip_serializing_if = "Option::is_none")]
        pub device_bound_required: Option<sts_model_base::unions::BoolOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors146;
}

/// Set the password policy profile
pub mod save_password_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-password-policy";
    pub const OPERATION_ID: &str = "savePasswordPolicy";

    /// The algorithm a newly stored password is hashed with: scrypt (RFC 7914), the
    /// default, or argon2id (RFC 9106, the OWASP Password Storage Cheat Sheet's
    /// first choice). A stored hash names its own algorithm and parameters and
    /// keeps verifying. One in another algorithm, or in the same algorithm at a
    /// strictly lower cost, is hashed again at the person's next verified sign-in.
    /// A same-algorithm hash already at least this cost is left. Client secrets,
    /// activation tokens, recovery codes and app passwords are not passwords and
    /// stay scrypt. Default `scrypt`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyHashAlgorithm {
        #[serde(rename = "scrypt")]
        Scrypt,
        #[serde(rename = "argon2id")]
        Argon2id,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// The shortest password this service will set, counted in characters
        /// (Unicode code points, so an emoji is one). The attribute is
        /// draft-behera-ldap-password-policy's. Twelve is the default; NIST SP
        /// 800-63B asks for at least 8, and 15 where a password is the only factor.
        /// Between 1 and 1024. Default 12.
        #[serde(rename = "minLength")]
        pub min_length: sts_model_base::unions::IntegerOrString,
        /// How many of a person's PREVIOUS passwords are remembered and refused.
        /// The current password is always refused as well while this is above 0, so
        /// 5 means a new password may be none of the last six. 0 turns the rule
        /// off. The draft's attribute, with the draft's meaning. Each remembered
        /// password is kept as the hash it was already stored as (argon2id or
        /// scrypt), in pwdHistory on the person's own entry, and checking a new
        /// password costs one hash comparison per one remembered. Between 0 and 24.
        /// Default 5.
        pub history: sts_model_base::unions::IntegerOrString,
        /// Always 0. A policy that asks for symbols is refused: ASVS 5.0.0 6.2.5
        /// requires that a password of any composition be accepted, so length is
        /// what this policy asks for. Between 0 and 16. Default 0.
        #[serde(rename = "minSymbols")]
        pub min_symbols: sts_model_base::unions::IntegerOrString,
        /// Always off. A policy that requires an uppercase letter is refused: ASVS
        /// 5.0.0 6.2.5 requires that a password of any composition be accepted.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "requireUppercase")]
        pub require_uppercase: sts_model_base::unions::BoolOrString,
        /// Always off. A policy that requires a number is refused: ASVS 5.0.0 6.2.5
        /// requires that a password of any composition be accepted.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.
        #[serde(rename = "requireDigit")]
        pub require_digit: sts_model_base::unions::BoolOrString,
        /// How long a password this service MAKES UP is — for a new user created
        /// from the console or /admin-api, an operator's Generate, and the
        /// product-mode bootstrap account. It must be at least the minimum length
        /// and at least twice the symbol count plus two. Twenty characters from a
        /// 90-character alphabet is about 130 bits. Between 12 and 128. Default 20.
        #[serde(rename = "generatedLength")]
        pub generated_length: sts_model_base::unions::IntegerOrString,
        /// The algorithm a newly stored password is hashed with: scrypt (RFC 7914),
        /// the default, or argon2id (RFC 9106, the OWASP Password Storage Cheat
        /// Sheet's first choice). A stored hash names its own algorithm and
        /// parameters and keeps verifying. One in another algorithm, or in the same
        /// algorithm at a strictly lower cost, is hashed again at the person's next
        /// verified sign-in. A same-algorithm hash already at least this cost is
        /// left. Client secrets, activation tokens, recovery codes and app
        /// passwords are not passwords and stay scrypt. Default `scrypt`.
        #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub hash_algorithm: Option<BodyHashAlgorithm>,
        /// The memory one argon2id hash uses, in kibibytes (m). 19456 KiB (19 MiB)
        /// is OWASP's minimum and the least this service will write. Raising it
        /// makes a stolen store slower to attack, and every sign-in uses that much
        /// more memory. Between 19456 and 1048576. Default 19456.
        #[serde(rename = "argon2Memory", default, skip_serializing_if = "Option::is_none")]
        pub argon2_memory: Option<sts_model_base::unions::IntegerOrString>,
        /// How many passes argon2id makes over its memory (t). 2 is OWASP's minimum
        /// at 19 MiB; each pass adds the same time again. Between 2 and 16. Default
        /// 2.
        #[serde(rename = "argon2Iterations", default, skip_serializing_if = "Option::is_none")]
        pub argon2_iterations: Option<sts_model_base::unions::IntegerOrString>,
        /// How many lanes argon2id divides its memory into (p). It is part of the
        /// hash, not a thread count: node computes a hash on one thread whatever
        /// this says. 1 is OWASP's figure. Between 1 and 16. Default 1.
        #[serde(rename = "argon2Parallelism", default, skip_serializing_if = "Option::is_none")]
        pub argon2_parallelism: Option<sts_model_base::unions::IntegerOrString>,
        /// scrypt's CPU and memory cost for a newly stored password while the
        /// algorithm is scrypt, as a power of two: 15 (the default) is N=32768.
        /// OWASP's table pairs it with the parallelism: 2^17 with p=1, 2^16 with
        /// p=2, 2^15 with p=3, 2^14 with p=5, or 2^13 with p=10. The default is
        /// 2^15 with p=3, one of those pairs. A parallelism below the pair for the
        /// chosen cost is refused. Between 13 and 20. Default 15.
        #[serde(rename = "scryptLogN", default, skip_serializing_if = "Option::is_none")]
        pub scrypt_log_n: Option<sts_model_base::unions::IntegerOrString>,
        /// scrypt's block size for a newly stored password while the algorithm is
        /// scrypt. Memory is about 128 × N × r bytes; 8 is the figure RFC 7914 and
        /// OWASP give. Between 8 and 16. Default 8.
        #[serde(rename = "scryptBlockSize", default, skip_serializing_if = "Option::is_none")]
        pub scrypt_block_size: Option<sts_model_base::unions::IntegerOrString>,
        /// scrypt's parallelism for a newly stored password while the algorithm is
        /// scrypt. Node computes it on one thread, so a higher value costs time
        /// rather than cores; the cost's description lists the pairs OWASP accepts.
        /// The default is 3. A value below OWASP's pair for the chosen cost is
        /// refused. Between 1 and 16. Default 3.
        #[serde(rename = "scryptParallelism", default, skip_serializing_if = "Option::is_none")]
        pub scrypt_parallelism: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors142;
}

/// Set the post-login activity policy profile
pub mod save_post_login_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-postLogin-policy";
    pub const OPERATION_ID: &str = "savePostLoginPolicy";

    /// leave: not asked. invite: asked to register a post-quantum passkey, and may
    /// always skip it. require: asked, and may skip it only until the allotted time
    /// has passed. Default `leave`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyNoPasskey {
        #[serde(rename = "leave")]
        Leave,
        #[serde(rename = "invite")]
        Invite,
        #[serde(rename = "require")]
        Require,
    }

    /// upgrade: the person uses their classical passkey once, then an ML-DSA
    /// passkey replaces it in place on the same authenticator — one passkey,
    /// nothing left behind. alongside: an ML-DSA passkey is added beside it, in the
    /// post-quantum lane where the realm offers two lanes, or on another
    /// authenticator where it offers one. automatic: alongside where the person's
    /// passkey policy offers two lanes, upgrade where it offers one. Default
    /// `automatic`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMethod {
        #[serde(rename = "automatic")]
        Automatic,
        #[serde(rename = "upgrade")]
        Upgrade,
        #[serde(rename = "alongside")]
        Alongside,
    }

    /// any: its key algorithm is ML-DSA. post-quantum: its key algorithm is ML-DSA
    /// AND its recorded attestation was signed with post-quantum algorithms
    /// throughout; a passkey with a classical attestation, or none recorded, does
    /// not count, and its holder is asked for one that does. Default `any`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttestation {
        #[serde(rename = "any")]
        Any,
        #[serde(rename = "post-quantum")]
        PostQuantum,
    }

    /// none: ML-DSA only. classical: after an ML-DSA registration fails on the
    /// device, a retry with the classical algorithms is offered (where the passkey
    /// policy allows one) — a classical passkey is better than a password, and its
    /// holder is asked for the migration later like anyone else's. Default `none`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyNoPasskeyFallback {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "classical")]
        Classical,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// OFF BY DEFAULT. On, every person this profile reaches who is due the
        /// activity below is asked to do it after signing in, before they are sent
        /// back to the application. A named profile with this off EXCLUDES whoever
        /// it is selected for: the members of the groups naming it, and a sign-in
        /// to an application naming it. (`true`/`false`, or `TRUE`/`FALSE` from a
        /// form.) Default false.
        pub enabled: sts_model_base::unions::BoolOrString,
        /// What is asked. pqc-passkey-migration: a person holding a passkey made
        /// with a classical algorithm is asked to register a post-quantum (ML-DSA)
        /// passkey. Whether the classical passkey is replaced in place or kept
        /// beside it is the method's to say (below). Nobody is asked where the
        /// realm offers no ML-DSA algorithm at registration (the default
        /// webauthn.algorithms does). Default `pqc-passkey-migration`.
        pub activity: String,
        /// How long Skip puts the activity off for that person. Between 1 and 90.
        /// Default 7.
        #[serde(rename = "snoozeDays")]
        pub snooze_days: sts_model_base::unions::IntegerOrString,
        /// Counted from the person's FIRST invitation. When it has passed, Skip is
        /// gone and the sign-in is held — no session is started — until the
        /// activity is done. 0 is no deadline: it can always be skipped. Between 0
        /// and 3650. Default 0.
        #[serde(rename = "graceDays")]
        pub grace_days: sts_model_base::unions::IntegerOrString,
        /// leave: not asked. invite: asked to register a post-quantum passkey, and
        /// may always skip it. require: asked, and may skip it only until the
        /// allotted time has passed. Default `leave`.
        #[serde(rename = "noPasskey")]
        pub no_passkey: BodyNoPasskey,
        /// upgrade: the person uses their classical passkey once, then an ML-DSA
        /// passkey replaces it in place on the same authenticator — one passkey,
        /// nothing left behind. alongside: an ML-DSA passkey is added beside it, in
        /// the post-quantum lane where the realm offers two lanes, or on another
        /// authenticator where it offers one. automatic: alongside where the
        /// person's passkey policy offers two lanes, upgrade where it offers one.
        /// Default `automatic`.
        pub method: BodyMethod,
        /// any: its key algorithm is ML-DSA. post-quantum: its key algorithm is
        /// ML-DSA AND its recorded attestation was signed with post-quantum
        /// algorithms throughout; a passkey with a classical attestation, or none
        /// recorded, does not count, and its holder is asked for one that does.
        /// Default `any`.
        pub attestation: BodyAttestation,
        /// none: ML-DSA only. classical: after an ML-DSA registration fails on the
        /// device, a retry with the classical algorithms is offered (where the
        /// passkey policy allows one) — a classical passkey is better than a
        /// password, and its holder is asked for the migration later like anyone
        /// else's. Default `none`.
        #[serde(rename = "noPasskeyFallback")]
        pub no_passkey_fallback: BodyNoPasskeyFallback,
        /// Ignored since #1135: a passkey has no role, so a person with none
        /// registers a passkey and nothing else is asked. Accepted so that an older
        /// body is not refused; not stored, not answered.
        #[serde(rename = "noPasskeyRole", default, skip_serializing_if = "Option::is_none")]
        pub no_passkey_role: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors151;
}

/// Set the service-account policy profile
pub mod save_service_account_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/save-serviceAccount-policy";
    pub const OPERATION_ID: &str = "saveServiceAccountPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which profile: `default`, or a named profile (lower-case letters, digits
        /// and hyphens), which is created by its first save.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// What the profile is for, for the next person. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A named profile only: the lowest matching precedence wins. Default 100.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<sts_model_base::unions::IntegerOrString>,
        /// OFF BY DEFAULT. On, the authentication policy's second-factor
        /// requirements do not apply to a service account in this realm, and nor
        /// does the refusal of a password alone at the password doors (#101). The
        /// account's amr still says pwd only, so a relying party asking for more is
        /// refused it. WEAKER: an account on a password alone is an account anyone
        /// with the password is. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default false.
        #[serde(rename = "exemptFromSecondFactor")]
        pub exempt_from_second_factor: sts_model_base::unions::BoolOrString,
        /// OFF BY DEFAULT. Off, the sign-in screen, the user portal and the admin
        /// console refuse a service account, whichever first factor it presents,
        /// and turning a person into a service account ends their browser sessions.
        /// A service account is used by a program, and a program has no business at
        /// a sign-in screen. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default false.
        #[serde(rename = "allowBrowserSignIn")]
        pub allow_browser_sign_in: sts_model_base::unions::BoolOrString,
        /// A bind on 389 or 636 (RFC 4513). Off, a service account's right password
        /// is refused there as a wrong one is. (`true`/`false`, or `TRUE`/`FALSE`
        /// from a form.) Default true.
        #[serde(rename = "allowLdapBind")]
        pub allow_ldap_bind: sts_model_base::unions::BoolOrString,
        /// A WS-Security UsernameToken sent to the security token service. Off, a
        /// service account's right password is refused there as a wrong one is.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "allowWsTrust")]
        pub allow_ws_trust: sts_model_base::unions::BoolOrString,
        /// HTTP Basic at /scim/v2 (RFC 7617). Off, a service account's right
        /// password is refused there as a wrong one is. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "allowScim")]
        pub allow_scim: sts_model_base::unions::BoolOrString,
        /// HTTP Basic at the /ssf endpoints (RFC 7617). Off, a service account's
        /// right password is refused there as a wrong one is. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "allowSsf")]
        pub allow_ssf: sts_model_base::unions::BoolOrString,
        /// HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3). Off, a service
        /// account's right password is refused there as a wrong one is.
        /// (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "allowEst")]
        pub allow_est: sts_model_base::unions::BoolOrString,
        /// An AS-REQ whose pre-authentication proves the password's key (RFC 4120),
        /// and MS-KKDCP. Off, a service account's right password is refused there
        /// as a wrong one is. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default true.
        #[serde(rename = "allowKerberos")]
        pub allow_kerberos: sts_model_base::unions::BoolOrString,
        /// grant_type=password at the token endpoint (RFC 6749 section 4.3), where
        /// the realm allows the grant at all. Off, a service account's right
        /// password is refused there as a wrong one is. (`true`/`false`, or
        /// `TRUE`/`FALSE` from a form.) Default true.
        #[serde(rename = "allowPasswordGrant")]
        pub allow_password_grant: sts_model_base::unions::BoolOrString,
        /// OFF BY DEFAULT. On, the service-accounts.rotate job gives every service
        /// account that names a push destination a new generated password each
        /// interval: pushed to the destination FIRST, its hash committed only after
        /// the push succeeds, the previous password kept for the overlap below. A
        /// failed push changes nothing. Cannot be turned on while this realm has no
        /// push destination. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default false.
        #[serde(rename = "rotationEnabled")]
        pub rotation_enabled: sts_model_base::unions::BoolOrString,
        /// How long a service account's password is kept before the job replaces
        /// it, counted from the last rotation (or the account's last password
        /// change). Between 1 and 3650. Default 30.
        #[serde(rename = "rotationIntervalDays")]
        pub rotation_interval_days: sts_model_base::unions::IntegerOrString,
        /// After a rotation the previous password is accepted for this long, so a
        /// consumer slow to read the new one is not refused — nor counted by risk
        /// scoring as guessing (#226). The previous Kerberos keys are kept as long.
        /// 0: the old password stops at once. Between 0 and 10080. Default 60.
        #[serde(rename = "rotationOverlapMinutes")]
        pub rotation_overlap_minutes: sts_model_base::unions::IntegerOrString,
        /// Drawn by the password policy's generator, so it meets that policy, and
        /// never shorter than its minimum length. Between 16 and 128. Default 32.
        #[serde(rename = "generatedLength")]
        pub generated_length: sts_model_base::unions::IntegerOrString,
        /// ON BY DEFAULT. The owner — a person or a group in this realm — is who
        /// answers for the account; a service account cannot be saved without one
        /// while this is on. (`true`/`false`, or `TRUE`/`FALSE` from a form.)
        /// Default true.
        #[serde(rename = "requireOwner")]
        pub require_owner: sts_model_base::unions::BoolOrString,
        /// A failed rotation is retried at the job's next run. After this many in a
        /// row the account is reported on Monitoring → Service accounts and logged
        /// as an alarm (STS-SVCACCT-0042). Between 1 and 100. Default 3.
        #[serde(rename = "rotationAlarmFailures")]
        pub rotation_alarm_failures: sts_model_base::unions::IntegerOrString,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors145;
}

/// How this realm's policy exports are signed, and whose it trusts
pub mod get_policy_transfer {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/policies/transfer";
    pub const OPERATION_ID: &str = "getPolicyTransfer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::PolicyTransferView;
}

/// Export this realm's policies as a signed JSON document
pub mod export_policies {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/transfer/export";
    pub const OPERATION_ID: &str = "exportPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policies to carry, each by its kind and its name. Absent: every
        /// policy this realm stores. A name this realm does not store is refused
        /// (STS-ADMIN-0937) and nothing is exported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<sts_model_management_components_3::PolicySelection>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::PolicyTransferAnswer;
}

/// Import a policy export into this realm
pub mod import_policies {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/transfer/import";
    pub const OPERATION_ID: &str = "importPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The export, as the JSON object `export` answered in `document` or as
        /// that JSON in a string.
        pub document: sts_model_management_components_3::PolicyTransferValue,
        /// An administrator's yes to trusting another realm's signer for policy
        /// imports in this realm. Ignored for this realm's own signer.
        #[serde(rename = "trustSigner", default, skip_serializing_if = "Option::is_none")]
        pub trust_signer: Option<bool>,
        /// With `trustSigner`: the SHA-256 fingerprint of the Issuing CA the
        /// inspection showed, in either spelling.
        #[serde(rename = "issuerFingerprint", default, skip_serializing_if = "Option::is_none")]
        pub issuer_fingerprint: Option<String>,
        /// The profiles to write, each by its kind and its name, as `inspect` lists
        /// them in `profiles`. Absent: every profile the export carries. A name the
        /// export does not carry is refused (STS-ADMIN-0938) before anything is
        /// trusted or written; the rest of the export is left unwritten.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<sts_model_management_components_3::PolicySelection>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::PolicyTransferAnswer;
}

/// Verify a policy export and say who signed it, writing nothing
pub mod inspect_policy_export {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/transfer/inspect";
    pub const OPERATION_ID: &str = "inspectPolicyExport";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The export, as the JSON object `export` answered in `document` or as
        /// that JSON in a string.
        pub document: sts_model_management_components_3::PolicyTransferValue,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::PolicyTransferAnswer;
}

/// Change a custom attribute of this realm
pub mod update_person_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/policies/update-person-attribute";
    pub const OPERATION_ID: &str = "updatePersonAttribute";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The attribute's name.
        pub name: String,
        /// What the pages draw beside the name. Kept when not sent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// What it is for; empty removes it. Kept when not sent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Whether a person sees their own values on the user portal. Kept when not
        /// sent; false also turns `portalEditable` off unless that is sent true.
        #[serde(rename = "portalVisible", default, skip_serializing_if = "Option::is_none")]
        pub portal_visible: Option<bool>,
        /// Whether a person may change their own values on the user portal. Kept
        /// when not sent; true turns `portalVisible` on.
        #[serde(rename = "portalEditable", default, skip_serializing_if = "Option::is_none")]
        pub portal_editable: Option<bool>,
        /// Accepted only as the definition's own syntax; any other is refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub syntax: Option<String>,
        /// Accepted only as the definition's own cardinality; any other is refused.
        #[serde(rename = "multiValued", default, skip_serializing_if = "Option::is_none")]
        pub multi_valued: Option<sts_model_base::unions::BoolOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors150;
}

/// The RISC account register: what state each account is in and how many events
/// of which type have been sent about it
pub mod get_risc {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/risc";
    pub const OPERATION_ID: &str = "getRisc";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::Risc;
}

/// The RISC account register, searched and paged — or one account with
/// everything that has been said about it
pub mod get_risc_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/risc/accounts";
    pub const OPERATION_ID: &str = "getRiscAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acctq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(rename = "accountsPage", default, skip_serializing_if = "Option::is_none")]
        pub accounts_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rappq: Option<String>,
        #[serde(rename = "rapplicationsPage", default, skip_serializing_if = "Option::is_none")]
        pub rapplications_page: Option<i64>,
        #[serde(rename = "streamsPage", default, skip_serializing_if = "Option::is_none")]
        pub streams_page: Option<i64>,
        #[serde(rename = "eventsPage", default, skip_serializing_if = "Option::is_none")]
        pub events_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::Risc;
}

/// Drop every row in the RISC account register
pub mod clear_risc_accounts {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risc/clear";
    pub const OPERATION_ID: &str = "clearRiscAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Send one RISC event about one account
pub mod emit_risc_event {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risc/emit";
    pub const OPERATION_ID: &str = "emitRiscEvent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The account it is about, from GET /admin-api/risc. A name no row carries
        /// is accepted and opens one.
        pub account_id: String,
        /// The event type: a short name such as `account-disabled`, or the whole
        /// URI.
        #[serde(rename = "type")]
        pub type_: String,
        /// The event-specific members, as JSON. Empty for a conforming specimen of
        /// the type, which is what eleven of the fourteen always are. Note the
        /// HYPHEN in `identifier-changed`'s `new-value`: it is the only hyphenated
        /// member name in any of the three vocabularies, and `new_value` is carried
        /// and silently ignored by a receiver.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<String>,
        /// Why, for a log. Sent as an object keyed by `risc.reasonLanguage`. It
        /// reaches the wire for ONE of the fourteen types — RISC gives the reason
        /// members to `credential-compromise` and to nothing else — and is dropped
        /// by the catalogue on any other, rather than being sent as a member the
        /// specification does not define.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason_admin: Option<String>,
        /// The same, in words meant for the person. Same one type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason_user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors111;
}

/// Put one account's RISC state back to where it started
pub mod reset_risc_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risc/reset-account";
    pub const OPERATION_ID: &str = "resetRiscAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The account.
        pub account_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// The risk datasets, a lookup, and the refused passwords
pub mod get_risk {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/risk";
    pub const OPERATION_ID: &str = "getRisk";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authenticator: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "assessmentsPage", default, skip_serializing_if = "Option::is_none")]
        pub assessments_page: Option<i64>,
        #[serde(rename = "subjectsPage", default, skip_serializing_if = "Option::is_none")]
        pub subjects_page: Option<i64>,
        #[serde(rename = "failuresPage", default, skip_serializing_if = "Option::is_none")]
        pub failures_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Store {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DatasetsItemVersionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dataset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub licence: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub attribution: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "sourceUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub source_uri: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sha256: Option<Option<String>>,
        #[serde(rename = "byteCount", default, skip_serializing_if = "Option::is_none")]
        pub byte_count: Option<f64>,
        #[serde(rename = "rowCount", default, skip_serializing_if = "Option::is_none")]
        pub row_count: Option<f64>,
        /// What was recorded of this version as it loaded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parameters: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub verification: Option<Option<String>>,
        #[serde(rename = "publishedAt", default, skip_serializing_if = "Option::is_none")]
        pub published_at: Option<f64>,
        #[serde(rename = "nextUpdateAt", default, skip_serializing_if = "Option::is_none")]
        pub next_update_at: Option<f64>,
        #[serde(rename = "fetchedAt", default, skip_serializing_if = "Option::is_none")]
        pub fetched_at: Option<f64>,
        #[serde(rename = "loadedAt", default, skip_serializing_if = "Option::is_none")]
        pub loaded_at: Option<f64>,
        #[serde(rename = "activatedAt", default, skip_serializing_if = "Option::is_none")]
        pub activated_at: Option<f64>,
        #[serde(rename = "supersededAt", default, skip_serializing_if = "Option::is_none")]
        pub superseded_at: Option<f64>,
        #[serde(rename = "rowsDeletedAt", default, skip_serializing_if = "Option::is_none")]
        pub rows_deleted_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub refusal: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub origin: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reloadable: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DatasetsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dataset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub formats: Option<Vec<String>>,
        #[serde(rename = "perRealm", default, skip_serializing_if = "Option::is_none")]
        pub per_realm: Option<bool>,
        #[serde(rename = "staleAfterMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub stale_after_ms: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "activeVersion", default, skip_serializing_if = "Option::is_none")]
        pub active_version: Option<String>,
        #[serde(rename = "previousVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub previous_version: Option<Option<String>>,
        #[serde(rename = "publishedAt", default, skip_serializing_if = "Option::is_none")]
        pub published_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub provider: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub attribution: Option<Option<String>>,
        #[serde(rename = "attributionUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub attribution_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub versions: Option<Vec<Answer200DatasetsItemVersionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormatsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItemAccepted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(rename = "termsDigest", default, skip_serializing_if = "Option::is_none")]
        pub terms_digest: Option<String>,
        #[serde(rename = "termsText", default, skip_serializing_if = "Option::is_none")]
        pub terms_text: Option<String>,
        #[serde(rename = "acceptedBy", default, skip_serializing_if = "Option::is_none")]
        pub accepted_by: Option<String>,
        #[serde(rename = "acceptedVia", default, skip_serializing_if = "Option::is_none")]
        pub accepted_via: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deployment: Option<String>,
        #[serde(rename = "pageDigest", default, skip_serializing_if = "Option::is_none")]
        pub page_digest: Option<String>,
        #[serde(rename = "acceptedAt", default, skip_serializing_if = "Option::is_none")]
        pub accepted_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub licence: Option<Option<String>>,
        #[serde(rename = "licenceName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub licence_name: Option<Option<String>>,
        #[serde(rename = "licenceUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub licence_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub attribution: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub terms: Option<Option<String>>,
        #[serde(rename = "termsUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub terms_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub supported: Option<bool>,
        #[serde(rename = "noAcceptance", default, skip_serializing_if = "Option::is_none")]
        pub no_acceptance: Option<bool>,
        #[serde(rename = "termsDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub terms_digest: Option<Option<String>>,
        #[serde(rename = "needsAcceptance", default, skip_serializing_if = "Option::is_none")]
        pub needs_acceptance: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accepted: Option<Answer200ProvidersItemAccepted>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub changed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LookupListsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dataset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub category: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Lookup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub prefix: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub geo: Option<sts_model_management_components_1::ChoiceOf32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asn: Option<sts_model_management_components_1::ChoiceOf32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lists: Option<Vec<Answer200LookupListsItem>>,
        /// The version of each dataset this was read from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub datasets: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributions: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesDataset>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticatorLookupModelStatusReportsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "effectiveDate", default, skip_serializing_if = "Option::is_none")]
        pub effective_date: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub comment: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticatorLookupModel {
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub description: Option<Option<String>>,
        #[serde(rename = "protocolFamily", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub protocol_family: Option<Option<String>>,
        #[serde(rename = "certificationLevel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub certification_level: Option<Option<String>>,
        #[serde(rename = "latestStatus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub latest_status: Option<Option<String>>,
        #[serde(rename = "latestStatusAt", default, skip_serializing_if = "Option::is_none")]
        pub latest_status_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compromised: Option<bool>,
        #[serde(rename = "statusReports", default, skip_serializing_if = "Option::is_none")]
        pub status_reports: Option<Vec<Answer200AuthenticatorLookupModelStatusReportsItem>>,
        /// The FIDO Alliance's MDS3 metadata statement, kept as the BLOB carried
        /// it: its shape is the FIDO Metadata Statement specification's, and which
        /// of its optional members a statement has is the vendor's.
        #[serde(rename = "metadataStatement", default, skip_serializing_if = "Option::is_none")]
        pub metadata_statement: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticatorLookup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input: Option<String>,
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<Answer200AuthenticatorLookupModel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributions: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesDataset>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssessmentsRowsItemSignalsItemTerms {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<f64>,
        #[serde(rename = "signIns", default, skip_serializing_if = "Option::is_none")]
        pub sign_ins: Option<f64>,
        #[serde(rename = "userSignIns", default, skip_serializing_if = "Option::is_none")]
        pub user_sign_ins: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssessmentsRowsItemSignalsItemDevice {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub own: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssessmentsRowsItemSignalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub score: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub factor: Option<Option<f64>>,
        /// Per level of the model.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub factors: Option<Option<serde_json::Map<String, serde_json::Value>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terms: Option<Answer200AssessmentsRowsItemSignalsItemTerms>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub evidence: Option<Option<String>>,
        #[serde(rename = "knownContext", default, skip_serializing_if = "Option::is_none")]
        pub known_context: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unknown: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capped: Option<String>,
        #[serde(rename = "listsSetAside", default, skip_serializing_if = "Option::is_none")]
        pub lists_set_aside: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<Answer200AssessmentsRowsItemSignalsItemDevice>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssessmentsRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub phase: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(rename = "userHref", default, skip_serializing_if = "Option::is_none")]
        pub user_href: Option<String>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub session_id: Option<Option<String>>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<String>>,
        #[serde(rename = "addressPrefix", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub address_prefix: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asn: Option<f64>,
        #[serde(rename = "asOrg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub as_org: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub country: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subdivision: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub city: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub latitude: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub longitude: Option<Option<f64>>,
        #[serde(rename = "accuracyKm", default, skip_serializing_if = "Option::is_none")]
        pub accuracy_km: Option<f64>,
        #[serde(rename = "ipLists", default, skip_serializing_if = "Option::is_none")]
        pub ip_lists: Option<Vec<String>>,
        #[serde(rename = "uaHash", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ua_hash: Option<Option<String>>,
        #[serde(rename = "uaFamily", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ua_family: Option<Option<String>>,
        #[serde(rename = "uaOs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ua_os: Option<Option<String>>,
        #[serde(rename = "uaPlatform", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ua_platform: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub bot: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ja4: Option<Option<String>>,
        #[serde(rename = "credentialKind", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub credential_kind: Option<Option<String>>,
        #[serde(rename = "credentialHash", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub credential_hash: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub aaguid: Option<Option<String>>,
        #[serde(rename = "authenticatorCert", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authenticator_cert: Option<Option<String>>,
        #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub backup_eligible: Option<Option<bool>>,
        #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub backup_state: Option<Option<bool>>,
        /// The version of each dataset read, and `stale` and `attributions` beside
        /// them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub datasets: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Vec<Answer200AssessmentsRowsItemSignalsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub score: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub decision: Option<Option<String>>,
        #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub policy_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub feedback: Option<Option<String>>,
        #[serde(rename = "feedbackAt", default, skip_serializing_if = "Option::is_none")]
        pub feedback_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Assessments {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200AssessmentsRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(rename = "userHref", default, skip_serializing_if = "Option::is_none")]
        pub user_href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub score: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub previous_level: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason: Option<Option<String>>,
        #[serde(rename = "lastAssessment", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_assessment: Option<Option<String>>,
        #[serde(rename = "crossedAt", default, skip_serializing_if = "Option::is_none")]
        pub crossed_at: Option<f64>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
        pub updated_at: Option<f64>,
        /// Each reaction taken, and the assessment that took it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub feedback: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FailuresStore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recording: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FailuresRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(rename = "userHref", default, skip_serializing_if = "Option::is_none")]
        pub user_href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub prefix: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asn: Option<f64>,
        #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error_code: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Failures {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<Answer200FailuresStore>,
        #[serde(rename = "windowDays", default, skip_serializing_if = "Option::is_none")]
        pub window_days: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offset: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200FailuresRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "realmOnly", default, skip_serializing_if = "Option::is_none")]
        pub realm_only: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<Answer200Store>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub datasets: Option<Vec<Answer200DatasetsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub formats: Option<Vec<Answer200FormatsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200ProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acceptances: Option<Vec<sts_model_management_components_4::WithIdProviderTermsDigest>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributions: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesDataset>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub redistribution: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lookup: Option<Answer200Lookup>,
        #[serde(rename = "authenticatorLookup", default, skip_serializing_if = "Option::is_none")]
        pub authenticator_lookup: Option<Answer200AuthenticatorLookup>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessments: Option<Answer200Assessments>,
        #[serde(rename = "assessmentsPaging", default, skip_serializing_if = "Option::is_none")]
        pub assessments_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subjects: Option<Vec<Answer200SubjectsItem>>,
        #[serde(rename = "subjectsPaging", default, skip_serializing_if = "Option::is_none")]
        pub subjects_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Vec<Answer200SignalsItem>>,
        #[serde(rename = "assessmentsInDatabase", default, skip_serializing_if = "Option::is_none")]
        pub assessments_in_database: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<Answer200Failures>,
        #[serde(rename = "failuresPaging", default, skip_serializing_if = "Option::is_none")]
        pub failures_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// Accept a dataset provider's current terms
pub mod accept_risk_provider_terms {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/accept-terms";
    pub const OPERATION_ID: &str = "acceptRiskProviderTerms";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProvider {
        #[serde(rename = "dbip-lite")]
        DbipLite,
        #[serde(rename = "ipinfo-lite")]
        IpinfoLite,
        #[serde(rename = "tor-project")]
        TorProject,
        #[serde(rename = "firehol")]
        Firehol,
        #[serde(rename = "operator")]
        Operator,
        #[serde(rename = "fido-mds3")]
        FidoMds3,
        #[serde(rename = "google-android-attestation")]
        GoogleAndroidAttestation,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub provider: BodyProvider,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Make a loaded version of a dataset the active one
pub mod activate_risk_dataset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/activate";
    pub const OPERATION_ID: &str = "activateRiskDataset";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub dataset: BodyDataset,
        pub version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Remove a version: delete its rows
pub mod delete_risk_dataset_version {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/delete";
    pub const OPERATION_ID: &str = "deleteRiskDatasetVersion";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub dataset: BodyDataset,
        pub version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Import one version of a risk dataset, and activate it
pub mod import_risk_dataset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/import";
    pub const OPERATION_ID: &str = "importRiskDataset";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyFormat {
        #[serde(rename = "dbip-city-csv")]
        DbipCityCsv,
        #[serde(rename = "dbip-country-csv")]
        DbipCountryCsv,
        #[serde(rename = "dbip-asn-csv")]
        DbipAsnCsv,
        #[serde(rename = "ipinfo-lite-csv")]
        IpinfoLiteCsv,
        #[serde(rename = "fido-mds3-jwt")]
        FidoMds3Jwt,
        #[serde(rename = "android-attestation-status-json")]
        AndroidAttestationStatusJson,
        #[serde(rename = "ip-list")]
        IpList,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProvider {
        #[serde(rename = "dbip-lite")]
        DbipLite,
        #[serde(rename = "ipinfo-lite")]
        IpinfoLite,
        #[serde(rename = "tor-project")]
        TorProject,
        #[serde(rename = "firehol")]
        Firehol,
        #[serde(rename = "operator")]
        Operator,
        #[serde(rename = "fido-mds3")]
        FidoMds3,
        #[serde(rename = "google-android-attestation")]
        GoogleAndroidAttestation,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub dataset: BodyDataset,
        pub format: BodyFormat,
        pub content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        /// An ISO 8601 date.
        #[serde(rename = "publishedAt", default, skip_serializing_if = "Option::is_none")]
        pub published_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<BodyProvider>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub licence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribution: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activate: Option<bool>,
        /// Accept the provider's current terms as part of this import. Without it,
        /// an import of a provider whose terms nobody has accepted is refused.
        #[serde(rename = "acceptTerms", default, skip_serializing_if = "Option::is_none")]
        pub accept_terms: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// The risk scoring system measured
pub mod get_risk_metrics {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/risk/metrics";
    pub const OPERATION_ID: &str = "getRiskMetrics";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryWindow {
        #[serde(rename = "1h")]
        V1h,
        #[serde(rename = "24h")]
        V24h,
        #[serde(rename = "7d")]
        V7d,
        #[serde(rename = "30d")]
        V30d,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<QueryWindow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Thresholds {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub medium: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub high: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssessmentsFeedback {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirmed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub denied: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Assessments {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subjects: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bots: Option<f64>,
        #[serde(rename = "meanScore", default, skip_serializing_if = "Option::is_none")]
        pub mean_score: Option<f64>,
        #[serde(rename = "maxScore", default, skip_serializing_if = "Option::is_none")]
        pub max_score: Option<f64>,
        #[serde(rename = "byLevel", default, skip_serializing_if = "Option::is_none")]
        pub by_level: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byDoor", default, skip_serializing_if = "Option::is_none")]
        pub by_door: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byDecision", default, skip_serializing_if = "Option::is_none")]
        pub by_decision: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byPhase", default, skip_serializing_if = "Option::is_none")]
        pub by_phase: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byCountry", default, skip_serializing_if = "Option::is_none")]
        pub by_country: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byBand", default, skip_serializing_if = "Option::is_none")]
        pub by_band: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "bySignal", default, skip_serializing_if = "Option::is_none")]
        pub by_signal: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "bySignalLevel", default, skip_serializing_if = "Option::is_none")]
        pub by_signal_level: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "bySignalFeedback", default, skip_serializing_if = "Option::is_none")]
        pub by_signal_feedback: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "scoreQuantiles", default, skip_serializing_if = "Option::is_none")]
        pub score_quantiles: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub feedback: Option<Answer200AssessmentsFeedback>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub series: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CalibrationMinimums {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessments: Option<f64>,
        #[serde(rename = "answersPerSignal", default, skip_serializing_if = "Option::is_none")]
        pub answers_per_signal: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CalibrationThresholdsMedium {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub share: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub suggested: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CalibrationThresholdsHigh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub share: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub suggested: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CalibrationThresholds {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub medium: Option<Answer200CalibrationThresholdsMedium>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub high: Option<Answer200CalibrationThresholdsHigh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CalibrationSignalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<f64>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fired: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub high: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub answered: Option<f64>,
        #[serde(rename = "notMe", default, skip_serializing_if = "Option::is_none")]
        pub not_me: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub suggested: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub advice: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Calibration {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessments: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub answered: Option<f64>,
        #[serde(rename = "notMeRate", default, skip_serializing_if = "Option::is_none")]
        pub not_me_rate: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub minimums: Option<Answer200CalibrationMinimums>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thresholds: Option<Answer200CalibrationThresholds>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Vec<Answer200CalibrationSignalsItem>>,
        #[serde(rename = "invalidFactors", default, skip_serializing_if = "Option::is_none")]
        pub invalid_factors: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<f64>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fired: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProcessDurationMs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub samples: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mean: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p50: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p95: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p99: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProcessReactions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub taken: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProcessRescore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runs: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub raised: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProcessBreachedPasswords {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub screened: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub breached: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unanswered: Option<f64>,
        #[serde(rename = "fromCache", default, skip_serializing_if = "Option::is_none")]
        pub from_cache: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Process {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<f64>,
        #[serde(rename = "durationMs", default, skip_serializing_if = "Option::is_none")]
        pub duration_ms: Option<Answer200ProcessDurationMs>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reactions: Option<Answer200ProcessReactions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rescore: Option<Answer200ProcessRescore>,
        #[serde(rename = "breachedPasswords", default, skip_serializing_if = "Option::is_none")]
        pub breached_passwords: Option<Answer200ProcessBreachedPasswords>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub windows: Option<Vec<String>>,
        #[serde(rename = "realmOnly", default, skip_serializing_if = "Option::is_none")]
        pub realm_only: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bands: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "windowMs", default, skip_serializing_if = "Option::is_none")]
        pub window_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<f64>,
        #[serde(rename = "bucketMs", default, skip_serializing_if = "Option::is_none")]
        pub bucket_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thresholds: Option<Answer200Thresholds>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessments: Option<Answer200Assessments>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub calibration: Option<Answer200Calibration>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub standings: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Vec<Answer200SignalsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process: Option<Answer200Process>,
    }
}

/// Download a removed version again, and load it
pub mod reload_risk_dataset_version {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/reload";
    pub const OPERATION_ID: &str = "reloadRiskDatasetVersion";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub dataset: BodyDataset,
        pub version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Make the previous version of a dataset active again
pub mod rollback_risk_dataset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/rollback";
    pub const OPERATION_ID: &str = "rollbackRiskDataset";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub dataset: BodyDataset,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Upload a risk dataset file, and import it
pub mod upload_risk_dataset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/risk/upload";
    pub const OPERATION_ID: &str = "uploadRiskDataset";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDataset {
        #[serde(rename = "geo.city")]
        GeoCity,
        #[serde(rename = "geo.country")]
        GeoCountry,
        #[serde(rename = "asn")]
        Asn,
        #[serde(rename = "iplist.tor-exit")]
        IplistTorExit,
        #[serde(rename = "iplist.reputation")]
        IplistReputation,
        #[serde(rename = "iplist.operator-deny")]
        IplistOperatorDeny,
        #[serde(rename = "iplist.operator-allow")]
        IplistOperatorAllow,
        #[serde(rename = "fido.mds3")]
        FidoMds3,
        #[serde(rename = "android.attestation-status")]
        AndroidAttestationStatus,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "dbip-city-csv")]
        DbipCityCsv,
        #[serde(rename = "dbip-country-csv")]
        DbipCountryCsv,
        #[serde(rename = "dbip-asn-csv")]
        DbipAsnCsv,
        #[serde(rename = "ipinfo-lite-csv")]
        IpinfoLiteCsv,
        #[serde(rename = "fido-mds3-jwt")]
        FidoMds3Jwt,
        #[serde(rename = "android-attestation-status-json")]
        AndroidAttestationStatusJson,
        #[serde(rename = "ip-list")]
        IpList,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryProvider {
        #[serde(rename = "dbip-lite")]
        DbipLite,
        #[serde(rename = "ipinfo-lite")]
        IpinfoLite,
        #[serde(rename = "tor-project")]
        TorProject,
        #[serde(rename = "firehol")]
        Firehol,
        #[serde(rename = "operator")]
        Operator,
        #[serde(rename = "fido-mds3")]
        FidoMds3,
        #[serde(rename = "google-android-attestation")]
        GoogleAndroidAttestation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryActivate {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryAcceptTerms {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOverrideSignature {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub dataset: QueryDataset,
        pub format: QueryFormat,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sha256: Option<String>,
        #[serde(rename = "publishedAt", default, skip_serializing_if = "Option::is_none")]
        pub published_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<QueryProvider>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub licence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribution: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activate: Option<QueryActivate>,
        #[serde(rename = "acceptTerms", default, skip_serializing_if = "Option::is_none")]
        pub accept_terms: Option<QueryAcceptTerms>,
        #[serde(rename = "overrideSignature", default, skip_serializing_if = "Option::is_none")]
        pub override_signature: Option<QueryOverrideSignature>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors8;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors8;
}

/// Who holds a role, and what requires one
pub mod get_roles {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/roles";
    pub const OPERATION_ID: &str = "getRoles";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "rolesPage", default, skip_serializing_if = "Option::is_none")]
        pub roles_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "requiringPage", default, skip_serializing_if = "Option::is_none")]
        pub requiring_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200DefaultRequired {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Policy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub enabled: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<bool>,
        #[serde(rename = "readsRisk", default, skip_serializing_if = "Option::is_none")]
        pub reads_risk: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200BuiltInItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RequiringItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unknown: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub configured: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requiring: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unsatisfiable: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MemberKindsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationChoicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RoleOwnersV2Item {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200RoleOwners {
        V1(Vec<String>),
        V2(Vec<Answer200RoleOwnersV2Item>),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RoleRequiredByItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RoleEntry {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operational: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RoleOwnership {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub marked: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protected: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Role {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "localName", default, skip_serializing_if = "Option::is_none")]
        pub local_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub console: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub native: Option<bool>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<bool>,
        #[serde(rename = "memberTypes", default, skip_serializing_if = "Option::is_none")]
        pub member_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<String>>,
        #[serde(rename = "conferredBy", default, skip_serializing_if = "Option::is_none")]
        pub conferred_by: Option<Vec<String>>,
        #[serde(rename = "ownerProtected", default, skip_serializing_if = "Option::is_none")]
        pub owner_protected: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<Answer200RoleOwners>,
        #[serde(rename = "requiredBy", default, skip_serializing_if = "Option::is_none")]
        pub required_by: Option<Vec<Answer200RoleRequiredByItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<Answer200RoleEntry>,
        #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
        pub max_owners: Option<f64>,
        #[serde(rename = "holderCount", default, skip_serializing_if = "Option::is_none")]
        pub holder_count: Option<f64>,
        #[serde(rename = "canWrite", default, skip_serializing_if = "Option::is_none")]
        pub can_write: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ownership: Option<Answer200RoleOwnership>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub container: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub storable: Option<bool>,
        #[serde(rename = "defaultRequired", default, skip_serializing_if = "Option::is_none")]
        pub default_required: Option<Answer200DefaultRequired>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<bool>,
        #[serde(rename = "claimName", default, skip_serializing_if = "Option::is_none")]
        pub claim_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200Policy>,
        #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
        pub built_in: Option<Vec<Answer200BuiltInItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<sts_model_management_components_4::WithDescriptionOkMessage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200PermissionsItem>>,
        #[serde(rename = "permissionIds", default, skip_serializing_if = "Option::is_none")]
        pub permission_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requiring: Option<Vec<Answer200RequiringItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(rename = "requiringPaging", default, skip_serializing_if = "Option::is_none")]
        pub requiring_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<Answer200Query>,
        #[serde(rename = "memberKinds", default, skip_serializing_if = "Option::is_none")]
        pub member_kinds: Option<Vec<Answer200MemberKindsItem>>,
        #[serde(rename = "issuanceKinds", default, skip_serializing_if = "Option::is_none")]
        pub issuance_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue>,
        #[serde(rename = "shownRoles", default, skip_serializing_if = "Option::is_none")]
        pub shown_roles: Option<sts_model_management_components_4::WithDescriptionOkMessage>,
        #[serde(rename = "applicationChoices", default, skip_serializing_if = "Option::is_none")]
        pub application_choices: Option<Vec<Answer200ApplicationChoicesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<Answer200Role>,
    }
}

/// Let a client confer a role on everybody signing in through it
pub mod add_role_conferring_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/add-conferring-client";
    pub const OPERATION_ID: &str = "addRoleConferringClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The client_id of the application that confers it.
        pub client: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
    }
}

/// Give somebody a role
pub mod add_role_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/add-member";
    pub const OPERATION_ID: &str = "addRoleMember";

    /// Which of the three lists the member goes in.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "group")]
        Group,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role being given.
        pub role: String,
        /// Which of the three lists the member goes in.
        pub kind: BodyKind,
        /// The person, group or application. Named `member` rather than `name` on
        /// purpose: `role` is the role's own name, and a body that confused the two
        /// would succeed and create something plausible.
        pub member: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors138;
}

/// Add one owner to a role
pub mod add_role_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/add-owner";
    pub const OPERATION_ID: &str = "addRoleOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The person or group to add.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors140;
}

/// Let a role authorize a permission
pub mod add_role_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/add-permission";
    pub const OPERATION_ID: &str = "addRolePermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The permission identifier, base + name.
        pub permission: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors139;
}

/// Make a role
pub mod create_role {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/create-role";
    pub const OPERATION_ID: &str = "createRole";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMemberTypesItem {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role's name.
        pub role: String,
        /// What it is for, for the next person.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// The ONE application this role belongs to (#310), by its identifier. The
        /// role is registered as `<role>@<application>` — two applications may each
        /// have a `reader` — and a token or assertion for that application carries
        /// it as `<role>`, no other application's at all. Omit it for a realm-wide
        /// role, whose name may not contain `@`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// A name for people to read (#93). The role's name is still what a token
        /// carries; this is its label. Optional.
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Who may hold it (#93): `user` (people, directly or through a group) and
        /// `application` (an application as itself). Empty is both. A member of an
        /// excluded kind is refused, already held or added later; the two console
        /// roles cannot be restricted. Omitted, both.
        #[serde(rename = "memberTypes", default, skip_serializing_if = "Option::is_none")]
        pub member_types: Option<Vec<BodyMemberTypesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }
}

/// Remove a role
pub mod delete_role {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/delete-role";
    pub const OPERATION_ID: &str = "deleteRole";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role to remove.
        pub role: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors137;
}

/// Change what a role says it is for, and who may hold it
pub mod describe_role {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/describe-role";
    pub const OPERATION_ID: &str = "describeRole";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMemberTypesItem {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The new description. An empty string clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// A name for people to read (#93). The role's name is still what a token
        /// carries; this is its label. Omitted, it is kept; an empty string clears
        /// it.
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Who may hold it (#93): `user` (people, directly or through a group) and
        /// `application` (an application as itself). Empty is both. A member of an
        /// excluded kind is refused, already held or added later; the two console
        /// roles cannot be restricted. Omitted, they are kept.
        #[serde(rename = "memberTypes", default, skip_serializing_if = "Option::is_none")]
        pub member_types: Option<Vec<BodyMemberTypesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }
}

/// Would this be issued?
pub mod preview_role_issuance {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/roles/preview";
    pub const OPERATION_ID: &str = "previewRoleIssuance";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QuerySubjectKind {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKind {
        #[serde(rename = "start-session")]
        StartSession,
        #[serde(rename = "issue-access-token")]
        IssueAccessToken,
        #[serde(rename = "issue-id-token")]
        IssueIdToken,
        #[serde(rename = "issue-refresh-token")]
        IssueRefreshToken,
        #[serde(rename = "issue-authorization-code")]
        IssueAuthorizationCode,
        #[serde(rename = "issue-saml-assertion")]
        IssueSamlAssertion,
        #[serde(rename = "issue-wsfed-token")]
        IssueWsfedToken,
        #[serde(rename = "issue-wstrust-token")]
        IssueWstrustToken,
        #[serde(rename = "issue-kerberos-ticket")]
        IssueKerberosTicket,
        #[serde(rename = "issue-certificate")]
        IssueCertificate,
        #[serde(rename = "create-account")]
        CreateAccount,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "subjectKind", default, skip_serializing_if = "Option::is_none")]
        pub subject_kind: Option<QuerySubjectKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<QueryKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Asked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "subjectKind", default, skip_serializing_if = "Option::is_none")]
        pub subject_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Risk {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Device {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refusal: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProtocolRefused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub declared: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Mechanism {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub satisfied: Option<Vec<String>>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ScopesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decision: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Transfer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
        pub decided_by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
        pub decided_by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub answered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<Answer200Asked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decision: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        /// The XACML response's `Status` element, which is the PDP's to word and
        /// can carry a status detail of any shape.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub risk: Option<Answer200Risk>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<Answer200Device>,
        #[serde(rename = "protocolRefused", default, skip_serializing_if = "Option::is_none")]
        pub protocol_refused: Option<Answer200ProtocolRefused>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanism: Option<Answer200Mechanism>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<Answer200ScopesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transfer: Option<Answer200Transfer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deferred: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exchange: Option<sts_model_management_components_2::ExchangePerRightVerdictRole>,
        #[serde(rename = "gnapRights", default, skip_serializing_if = "Option::is_none")]
        pub gnap_rights: Option<Vec<sts_model_management_components_2::ExchangePerRightVerdictRole>>,
    }
}

/// Stop a client conferring a role
pub mod remove_role_conferring_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/remove-conferring-client";
    pub const OPERATION_ID: &str = "removeRoleConferringClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The client_id to take off.
        pub client: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
    }
}

/// Take a role away
pub mod remove_role_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/remove-member";
    pub const OPERATION_ID: &str = "removeRoleMember";

    /// Which list to remove it from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "group")]
        Group,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role being taken away.
        pub role: String,
        /// Which list to remove it from.
        pub kind: BodyKind,
        /// The person, group or application.
        pub member: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors138;
}

/// Take one owner off a role
pub mod remove_role_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/remove-owner";
    pub const OPERATION_ID: &str = "removeRoleOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The owner's DN.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors140;
}

/// Stop a role authorizing a permission
pub mod remove_role_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/roles/remove-permission";
    pub const OPERATION_ID: &str = "removeRolePermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The role.
        pub role: String,
        /// The permission identifier.
        pub permission: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors139;
}

/// How long an issued assertion is valid, and the clock skew written into it
pub mod get_saml_assertions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/saml-assertions";
    pub const OPERATION_ID: &str = "getSamlAssertions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Assertions {
        #[serde(rename = "saml2LifetimeMin", default, skip_serializing_if = "Option::is_none")]
        pub saml2_lifetime_min: Option<f64>,
        #[serde(rename = "saml11LifetimeMin", default, skip_serializing_if = "Option::is_none")]
        pub saml11_lifetime_min: Option<f64>,
        #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
        pub clock_skew_s: Option<f64>,
        #[serde(rename = "saml2WindowS", default, skip_serializing_if = "Option::is_none")]
        pub saml2_window_s: Option<f64>,
        #[serde(rename = "saml11WindowS", default, skip_serializing_if = "Option::is_none")]
        pub saml11_window_s: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PerApplicationItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssertionsIssuedByKindItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<f64>,
        #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
        pub no_expiry: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AssertionsIssued {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forgotten: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cap: Option<f64>,
        #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
        pub by_kind: Option<Vec<Answer200AssertionsIssuedByKindItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Context {
        #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub config_file: Option<Option<String>>,
        #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub defaults_file: Option<Option<String>>,
        #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
        pub persists_appconfig: Option<bool>,
        #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
        pub persists_realms: Option<bool>,
        #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
        pub persistence_mode: Option<String>,
        #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
        pub in_realm: Option<bool>,
        #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm_id: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kind: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assertions: Option<Answer200Assertions>,
        #[serde(rename = "perApplication", default, skip_serializing_if = "Option::is_none")]
        pub per_application: Option<Vec<Answer200PerApplicationItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::WithGroupSettingsConfigFile3>,
        #[serde(rename = "assertionsIssued", default, skip_serializing_if = "Option::is_none")]
        pub assertions_issued: Option<Answer200AssertionsIssued>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub now: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<Answer200Context>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        /// Each setting in seconds, by key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seconds: Option<serde_json::Map<String, serde_json::Value>>,
    }
}

/// Put the SAML assertion settings back
pub mod reset_saml_assertions {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-assertions/defaults";
    pub const OPERATION_ID: &str = "resetSamlAssertions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors72;
}

/// Set one or more of the SAML assertion settings
pub mod set_saml_assertions {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-assertions/set";
    pub const OPERATION_ID: &str = "setSamlAssertions";

    /// Encryption algorithm
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySaml2EncryptionAlgorithm {
        #[serde(rename = "aes256-gcm")]
        Aes256Gcm,
        #[serde(rename = "aes128-gcm")]
        Aes128Gcm,
        #[serde(rename = "aes256-cbc")]
        Aes256Cbc,
        #[serde(rename = "aes128-cbc")]
        Aes128Cbc,
    }

    /// Key transport algorithm
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySaml2KeyTransportAlgorithm {
        #[serde(rename = "rsa-oaep-mgf1p")]
        RsaOaepMgf1p,
        #[serde(rename = "rsa-oaep")]
        RsaOaep,
        #[serde(rename = "rsa-1_5")]
        Rsa15,
    }

    /// One property per setting, named by its dot path, BUILT from the list this
    /// action refuses against rather than typed here — it named three of them for
    /// months while the action accepted sixteen. The lifetimes are in MINUTES and
    /// the skew and the artifact lifetimes are in SECONDS; each row of the GET
    /// carries its own unit and bounds.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Assertion lifetime (minutes)
        #[serde(rename = "saml2.assertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
        pub saml2_assertion_lifetime_min: Option<i64>,
        /// Sign the assertion
        #[serde(rename = "saml2.signAssertion", default, skip_serializing_if = "Option::is_none")]
        pub saml2_sign_assertion: Option<bool>,
        /// Sign the response
        #[serde(rename = "saml2.signResponse", default, skip_serializing_if = "Option::is_none")]
        pub saml2_sign_response: Option<bool>,
        /// Default NameID format
        #[serde(rename = "saml2.nameIdFormat", default, skip_serializing_if = "Option::is_none")]
        pub saml2_name_id_format: Option<String>,
        /// Artifact lifetime (seconds)
        #[serde(rename = "saml2.artifactTtlS", default, skip_serializing_if = "Option::is_none")]
        pub saml2_artifact_ttl_s: Option<i64>,
        /// Encrypt the assertion
        #[serde(rename = "saml2.encryptAssertion", default, skip_serializing_if = "Option::is_none")]
        pub saml2_encrypt_assertion: Option<bool>,
        /// Encryption algorithm
        #[serde(rename = "saml2.encryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub saml2_encryption_algorithm: Option<BodySaml2EncryptionAlgorithm>,
        /// Key transport algorithm
        #[serde(rename = "saml2.keyTransportAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub saml2_key_transport_algorithm: Option<BodySaml2KeyTransportAlgorithm>,
        /// Encrypt the NameID in a LogoutRequest
        #[serde(rename = "saml2.encryptLogoutNameId", default, skip_serializing_if = "Option::is_none")]
        pub saml2_encrypt_logout_name_id: Option<bool>,
        /// Assertion lifetime (minutes)
        #[serde(rename = "saml11.assertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
        pub saml11_assertion_lifetime_min: Option<i64>,
        /// Sign the assertion
        #[serde(rename = "saml11.signAssertion", default, skip_serializing_if = "Option::is_none")]
        pub saml11_sign_assertion: Option<bool>,
        /// Sign the response
        #[serde(rename = "saml11.signResponse", default, skip_serializing_if = "Option::is_none")]
        pub saml11_sign_response: Option<bool>,
        /// Default NameIdentifier format
        #[serde(rename = "saml11.nameIdFormat", default, skip_serializing_if = "Option::is_none")]
        pub saml11_name_id_format: Option<String>,
        /// Artifact lifetime (seconds)
        #[serde(rename = "saml11.artifactTtlS", default, skip_serializing_if = "Option::is_none")]
        pub saml11_artifact_ttl_s: Option<i64>,
        /// Assertion lifetime (minutes)
        #[serde(rename = "wsfed.assertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
        pub wsfed_assertion_lifetime_min: Option<i64>,
        /// Assertion clock skew (s)
        #[serde(rename = "saml.clockSkewS", default, skip_serializing_if = "Option::is_none")]
        pub saml_clock_skew_s: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors72;
}

/// The SAML applications a sign-in may be started here for, with each one's
/// link
pub mod get_saml_idp_initiated_applications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/saml-idp-initiated";
    pub const OPERATION_ID: &str = "getSamlIdpInitiatedApplications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "idpInitiatedPage", default, skip_serializing_if = "Option::is_none")]
        pub idp_initiated_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IdpInitiatedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(rename = "launchUrl", default, skip_serializing_if = "Option::is_none")]
        pub launch_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub endpoint: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmSwitchesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(rename = "idpInitiated", default, skip_serializing_if = "Option::is_none")]
        pub idp_initiated: Option<Vec<Answer200IdpInitiatedItem>>,
        #[serde(rename = "idpInitiatedPaging", default, skip_serializing_if = "Option::is_none")]
        pub idp_initiated_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(rename = "realmSwitches", default, skip_serializing_if = "Option::is_none")]
        pub realm_switches: Option<Vec<Answer200RealmSwitchesItem>>,
    }
}

/// Every SAML 1.1 relying party, and the endpoints each is configured from
pub mod get_saml11_relying_parties {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/saml11";
    pub const OPERATION_ID: &str = "getSaml11RelyingParties";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rp: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RelyingPartiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<f64>,
        #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
        pub first_seen: Option<String>,
        #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
        pub last_seen: Option<String>,
        #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
        pub assertion_consumer_services: Option<Vec<String>>,
        #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
        pub name_id_formats: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slug: Option<Option<String>>,
        #[serde(rename = "idpProviderId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub idp_provider_id: Option<Option<String>>,
        #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
        pub metadata_url: Option<String>,
        #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
        pub sso_url: Option<String>,
        #[serde(rename = "responderUrl", default, skip_serializing_if = "Option::is_none")]
        pub responder_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(rename = "relyingParties", default, skip_serializing_if = "Option::is_none")]
        pub relying_parties: Option<Vec<Answer200RelyingPartiesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage3>,
        #[serde(rename = "unscopedMetadata", default, skip_serializing_if = "Option::is_none")]
        pub unscoped_metadata: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_4::WithPageGroupsSettingCount2>,
        #[serde(rename = "artifactsAwaitingResolution", default, skip_serializing_if = "Option::is_none")]
        pub artifacts_awaiting_resolution: Option<f64>,
        #[serde(rename = "assertionsHeldByReference", default, skip_serializing_if = "Option::is_none")]
        pub assertions_held_by_reference: Option<f64>,
        #[serde(rename = "flowsHeldForSignIn", default, skip_serializing_if = "Option::is_none")]
        pub flows_held_for_sign_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<bool>,
        #[serde(rename = "identifierLooksGuessed", default, skip_serializing_if = "Option::is_none")]
        pub identifier_looks_guessed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<f64>,
        #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
        pub assertion_consumer_services: Option<Vec<String>>,
        #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
        pub name_id_formats: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slug: Option<Option<String>>,
        #[serde(rename = "idpProviderId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub idp_provider_id: Option<Option<String>>,
        #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
        pub metadata_url: Option<String>,
        #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
        pub sso_url: Option<String>,
        #[serde(rename = "responderUrl", default, skip_serializing_if = "Option::is_none")]
        pub responder_url: Option<String>,
    }
}

/// Register a relying party and its assertion consumer
pub mod register_saml11_relying_party {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml11/register";
    pub const OPERATION_ID: &str = "registerSaml11RelyingParty";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relying party's identifier.
        pub rp: String,
        /// The assertion consumer service URL registered on the relying party.
        pub shire: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Every SAML 2.0 service provider, and the endpoints each is configured from
pub mod get_saml2_service_providers {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/saml2";
    pub const OPERATION_ID: &str = "getSaml2ServiceProviders";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sp: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "mdqRefusedPage", default, skip_serializing_if = "Option::is_none")]
        pub mdq_refused_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServiceProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<f64>,
        #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
        pub first_seen: Option<String>,
        #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
        pub last_seen: Option<String>,
        #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
        pub assertion_consumer_services: Option<Vec<String>>,
        #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
        pub single_logout_services: Option<Vec<String>>,
        #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
        pub name_id_formats: Option<Vec<String>>,
        #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
        pub response_bindings: Option<Vec<String>>,
        #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
        pub last_request_signed: Option<bool>,
        #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
        pub last_request_verification: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slug: Option<Option<String>>,
        #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub idp_entity_id: Option<Option<String>>,
        #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
        pub metadata_url: Option<String>,
        #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
        pub sso_url: Option<String>,
        #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
        pub slo_url: Option<String>,
        #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
        pub ars_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MdqRefusedItem {
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub first_at: Option<Option<String>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LastRequestVerification {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binding: Option<String>,
        #[serde(rename = "signatureMethod", default, skip_serializing_if = "Option::is_none")]
        pub signature_method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub weak: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignedRequestsRequired {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MetadataRefresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub last_attempt_at: Option<String>,
        #[serde(rename = "lastSuccessAt", default, skip_serializing_if = "Option::is_none")]
        pub last_success_at: Option<String>,
        #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
        pub failing_since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MetadataAssertionConsumerServicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub index: Option<String>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub is_default: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binding: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MetadataSingleLogoutServicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binding: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(rename = "responseLocation", default, skip_serializing_if = "Option::is_none")]
        pub response_location: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Metadata {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "stateWhy", default, skip_serializing_if = "Option::is_none")]
        pub state_why: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "staleAt", default, skip_serializing_if = "Option::is_none")]
        pub stale_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refreshable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refresh: Option<Answer200MetadataRefresh>,
        #[serde(rename = "refresherEnabled", default, skip_serializing_if = "Option::is_none")]
        pub refresher_enabled: Option<bool>,
        #[serde(rename = "refresherRunning", default, skip_serializing_if = "Option::is_none")]
        pub refresher_running: Option<bool>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<f64>,
        #[serde(rename = "trustAnchorProblems", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchor_problems: Option<Vec<String>>,
        #[serde(rename = "mdqUrl", default, skip_serializing_if = "Option::is_none")]
        pub mdq_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consumed: Option<bool>,
        #[serde(rename = "consumedAt", default, skip_serializing_if = "Option::is_none")]
        pub consumed_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub how: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signature: Option<String>,
        #[serde(rename = "signingCertificateConfigured", default, skip_serializing_if = "Option::is_none")]
        pub signing_certificate_configured: Option<bool>,
        #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none")]
        pub valid_until: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(rename = "cacheDuration", default, skip_serializing_if = "Option::is_none")]
        pub cache_duration: Option<String>,
        #[serde(rename = "authnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
        pub authn_requests_signed: Option<bool>,
        #[serde(rename = "wantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
        pub want_assertions_signed: Option<bool>,
        #[serde(rename = "wantAssertionsEncrypted", default, skip_serializing_if = "Option::is_none")]
        pub want_assertions_encrypted: Option<bool>,
        #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
        pub name_id_formats: Option<Vec<String>>,
        #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
        pub assertion_consumer_services: Option<Vec<Answer200MetadataAssertionConsumerServicesItem>>,
        #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
        pub single_logout_services: Option<Vec<Answer200MetadataSingleLogoutServicesItem>>,
        #[serde(rename = "encryptionCertificate", default, skip_serializing_if = "Option::is_none")]
        pub encryption_certificate: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(rename = "serviceProviders", default, skip_serializing_if = "Option::is_none")]
        pub service_providers: Option<Vec<Answer200ServiceProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage3>,
        #[serde(rename = "unscopedMetadata", default, skip_serializing_if = "Option::is_none")]
        pub unscoped_metadata: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_4::WithPageGroupsSettingCount2>,
        #[serde(rename = "artifactsAwaitingResolution", default, skip_serializing_if = "Option::is_none")]
        pub artifacts_awaiting_resolution: Option<f64>,
        #[serde(rename = "requestsHeldForSignIn", default, skip_serializing_if = "Option::is_none")]
        pub requests_held_for_sign_in: Option<f64>,
        #[serde(rename = "mdqRefused", default, skip_serializing_if = "Option::is_none")]
        pub mdq_refused: Option<Vec<Answer200MdqRefusedItem>>,
        #[serde(rename = "mdqRefusedPaging", default, skip_serializing_if = "Option::is_none")]
        pub mdq_refused_paging: Option<sts_model_management_components_4::WithPagePagesPerPage3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<f64>,
        #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
        pub assertion_consumer_services: Option<Vec<String>>,
        #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
        pub single_logout_services: Option<Vec<String>>,
        #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
        pub name_id_formats: Option<Vec<String>>,
        #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
        pub response_bindings: Option<Vec<String>>,
        #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
        pub last_request_signed: Option<bool>,
        #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
        pub last_request_verification: Option<Answer200LastRequestVerification>,
        #[serde(rename = "signingCertificate", default, skip_serializing_if = "Option::is_none")]
        pub signing_certificate: Option<String>,
        #[serde(rename = "signingCertificates", default, skip_serializing_if = "Option::is_none")]
        pub signing_certificates: Option<Vec<String>>,
        #[serde(rename = "observedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
        pub observed_signing_certificate: Option<String>,
        #[serde(rename = "signedRequestsRequired", default, skip_serializing_if = "Option::is_none")]
        pub signed_requests_required: Option<Answer200SignedRequestsRequired>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metadata: Option<Answer200Metadata>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slug: Option<Option<String>>,
        #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub idp_entity_id: Option<Option<String>>,
        #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
        pub metadata_url: Option<String>,
        #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
        pub sso_url: Option<String>,
        #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
        pub slo_url: Option<String>,
        #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
        pub ars_url: Option<String>,
    }
}

/// Trust the certificate a signed request carried
pub mod confirm_saml2_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/confirm-signing-certificate";
    pub const OPERATION_ID: &str = "confirmSaml2SigningCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Discard the certificate a signed request carried
pub mod discard_saml2_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/discard-signing-certificate";
    pub const OPERATION_ID: &str = "discardSaml2SigningCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Import a service provider from the MDQ responder
pub mod import_saml2_metadata_from_mdq {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/mdq-import";
    pub const OPERATION_ID: &str = "importSaml2MetadataFromMdq";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors83;
}

/// Fetch a service provider's metadata again, now
pub mod refresh_saml2_metadata {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/refresh-metadata";
    pub const OPERATION_ID: &str = "refreshSaml2Metadata";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors83;
}

/// Register a service provider by entityID
pub mod register_saml2_service_provider {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/register";
    pub const OPERATION_ID: &str = "registerSaml2ServiceProvider";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service provider's entityID.
        pub sp: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Take a logout return address off a service provider
pub mod remove_saml2_logout_service {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/remove-logout-service";
    pub const OPERATION_ID: &str = "removeSaml2LogoutService";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
        /// The exact value to remove.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Take one registered signing certificate off a service provider
pub mod remove_saml2_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/remove-signing-certificate";
    pub const OPERATION_ID: &str = "removeSaml2SigningCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
        /// The certificate to remove.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Declare where this service provider's LogoutResponse goes
pub mod add_saml2_logout_service {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/set-logout-service";
    pub const OPERATION_ID: &str = "addSaml2LogoutService";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service provider's entityID.
        pub sp: String,
        /// An absolute URL.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Require this service provider's metadata to be signed with one key
pub mod set_saml2_metadata_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/set-metadata-signing-certificate";
    pub const OPERATION_ID: &str = "setSaml2MetadataSigningCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
        /// Base64 DER or PEM; empty clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Replace the certificates this service provider's signatures are verified
/// against
pub mod set_saml2_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/set-signing-certificate";
    pub const OPERATION_ID: &str = "setSaml2SigningCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub sp: String,
        /// Base64 DER or PEM; empty clears the list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors82;
}

/// Consume a service provider's metadata document
pub mod upload_saml2_metadata {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml2/upload-metadata";
    pub const OPERATION_ID: &str = "uploadSaml2Metadata";

    /// The declared SAML family selected in the application configuration. When
    /// omitted, SAML 1.1 is selected only for an application declared for SAML 1.1
    /// alone.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyFamily {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    /// An uploaded metadata file, decoded as text by the static console.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyFile {
        /// The uploaded file name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The uploaded metadata document.
        pub text: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service provider's entityID — which the document must name.
        pub sp: String,
        /// The declared SAML family selected in the application configuration. When
        /// omitted, SAML 1.1 is selected only for an application declared for SAML
        /// 1.1 alone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<BodyFamily>,
        /// The metadata document, as XML.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<String>,
        /// An uploaded metadata file, decoded as text by the static console.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<BodyFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors83;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "clearPasskeyClient" => Some(serde_json::from_value::<clear_passkey_client::Body>(value.clone()).map(|_| ())),
        "clearPasskeyClients" => Some(serde_json::from_value::<clear_passkey_clients::Body>(value.clone()).map(|_| ())),
        "definePersonAttribute" => Some(serde_json::from_value::<define_person_attribute::Body>(value.clone()).map(|_| ())),
        "deleteNamedAuthnPolicy" => Some(serde_json::from_value::<delete_named_authn_policy::Body>(value.clone()).map(|_| ())),
        "removePersonAttribute" => Some(serde_json::from_value::<remove_person_attribute::Body>(value.clone()).map(|_| ())),
        "resetAttributesPolicy" => Some(serde_json::from_value::<reset_attributes_policy::Body>(value.clone()).map(|_| ())),
        "resetAuthnPolicy" => Some(serde_json::from_value::<reset_authn_policy::Body>(value.clone()).map(|_| ())),
        "resetLocalePolicy" => Some(serde_json::from_value::<reset_locale_policy::Body>(value.clone()).map(|_| ())),
        "resetPasskeyPolicy" => Some(serde_json::from_value::<reset_passkey_policy::Body>(value.clone()).map(|_| ())),
        "resetPasswordPolicy" => Some(serde_json::from_value::<reset_password_policy::Body>(value.clone()).map(|_| ())),
        "resetPostLoginPolicy" => Some(serde_json::from_value::<reset_post_login_policy::Body>(value.clone()).map(|_| ())),
        "resetServiceAccountPolicy" => Some(serde_json::from_value::<reset_service_account_policy::Body>(value.clone()).map(|_| ())),
        "saveAttributesPolicy" => Some(serde_json::from_value::<save_attributes_policy::Body>(value.clone()).map(|_| ())),
        "saveAuthnPolicy" => Some(serde_json::from_value::<save_authn_policy::Body>(value.clone()).map(|_| ())),
        "saveLocalePolicy" => Some(serde_json::from_value::<save_locale_policy::Body>(value.clone()).map(|_| ())),
        "saveNamedAuthnPolicy" => Some(serde_json::from_value::<save_named_authn_policy::Body>(value.clone()).map(|_| ())),
        "savePasskeyPolicy" => Some(serde_json::from_value::<save_passkey_policy::Body>(value.clone()).map(|_| ())),
        "savePasswordPolicy" => Some(serde_json::from_value::<save_password_policy::Body>(value.clone()).map(|_| ())),
        "savePostLoginPolicy" => Some(serde_json::from_value::<save_post_login_policy::Body>(value.clone()).map(|_| ())),
        "saveServiceAccountPolicy" => Some(serde_json::from_value::<save_service_account_policy::Body>(value.clone()).map(|_| ())),
        "exportPolicies" => Some(serde_json::from_value::<export_policies::Body>(value.clone()).map(|_| ())),
        "importPolicies" => Some(serde_json::from_value::<import_policies::Body>(value.clone()).map(|_| ())),
        "inspectPolicyExport" => Some(serde_json::from_value::<inspect_policy_export::Body>(value.clone()).map(|_| ())),
        "updatePersonAttribute" => Some(serde_json::from_value::<update_person_attribute::Body>(value.clone()).map(|_| ())),
        "clearRiscAccounts" => Some(serde_json::from_value::<clear_risc_accounts::Body>(value.clone()).map(|_| ())),
        "emitRiscEvent" => Some(serde_json::from_value::<emit_risc_event::Body>(value.clone()).map(|_| ())),
        "resetRiscAccount" => Some(serde_json::from_value::<reset_risc_account::Body>(value.clone()).map(|_| ())),
        "acceptRiskProviderTerms" => Some(serde_json::from_value::<accept_risk_provider_terms::Body>(value.clone()).map(|_| ())),
        "activateRiskDataset" => Some(serde_json::from_value::<activate_risk_dataset::Body>(value.clone()).map(|_| ())),
        "deleteRiskDatasetVersion" => Some(serde_json::from_value::<delete_risk_dataset_version::Body>(value.clone()).map(|_| ())),
        "importRiskDataset" => Some(serde_json::from_value::<import_risk_dataset::Body>(value.clone()).map(|_| ())),
        "reloadRiskDatasetVersion" => Some(serde_json::from_value::<reload_risk_dataset_version::Body>(value.clone()).map(|_| ())),
        "rollbackRiskDataset" => Some(serde_json::from_value::<rollback_risk_dataset::Body>(value.clone()).map(|_| ())),
        "addRoleConferringClient" => Some(serde_json::from_value::<add_role_conferring_client::Body>(value.clone()).map(|_| ())),
        "addRoleMember" => Some(serde_json::from_value::<add_role_member::Body>(value.clone()).map(|_| ())),
        "addRoleOwner" => Some(serde_json::from_value::<add_role_owner::Body>(value.clone()).map(|_| ())),
        "addRolePermission" => Some(serde_json::from_value::<add_role_permission::Body>(value.clone()).map(|_| ())),
        "createRole" => Some(serde_json::from_value::<create_role::Body>(value.clone()).map(|_| ())),
        "deleteRole" => Some(serde_json::from_value::<delete_role::Body>(value.clone()).map(|_| ())),
        "describeRole" => Some(serde_json::from_value::<describe_role::Body>(value.clone()).map(|_| ())),
        "removeRoleConferringClient" => Some(serde_json::from_value::<remove_role_conferring_client::Body>(value.clone()).map(|_| ())),
        "removeRoleMember" => Some(serde_json::from_value::<remove_role_member::Body>(value.clone()).map(|_| ())),
        "removeRoleOwner" => Some(serde_json::from_value::<remove_role_owner::Body>(value.clone()).map(|_| ())),
        "removeRolePermission" => Some(serde_json::from_value::<remove_role_permission::Body>(value.clone()).map(|_| ())),
        "resetSamlAssertions" => Some(serde_json::from_value::<reset_saml_assertions::Body>(value.clone()).map(|_| ())),
        "setSamlAssertions" => Some(serde_json::from_value::<set_saml_assertions::Body>(value.clone()).map(|_| ())),
        "registerSaml11RelyingParty" => Some(serde_json::from_value::<register_saml11_relying_party::Body>(value.clone()).map(|_| ())),
        "confirmSaml2SigningCertificate" => Some(serde_json::from_value::<confirm_saml2_signing_certificate::Body>(value.clone()).map(|_| ())),
        "discardSaml2SigningCertificate" => Some(serde_json::from_value::<discard_saml2_signing_certificate::Body>(value.clone()).map(|_| ())),
        "importSaml2MetadataFromMdq" => Some(serde_json::from_value::<import_saml2_metadata_from_mdq::Body>(value.clone()).map(|_| ())),
        "refreshSaml2Metadata" => Some(serde_json::from_value::<refresh_saml2_metadata::Body>(value.clone()).map(|_| ())),
        "registerSaml2ServiceProvider" => Some(serde_json::from_value::<register_saml2_service_provider::Body>(value.clone()).map(|_| ())),
        "removeSaml2LogoutService" => Some(serde_json::from_value::<remove_saml2_logout_service::Body>(value.clone()).map(|_| ())),
        "removeSaml2SigningCertificate" => Some(serde_json::from_value::<remove_saml2_signing_certificate::Body>(value.clone()).map(|_| ())),
        "addSaml2LogoutService" => Some(serde_json::from_value::<add_saml2_logout_service::Body>(value.clone()).map(|_| ())),
        "setSaml2MetadataSigningCertificate" => Some(serde_json::from_value::<set_saml2_metadata_signing_certificate::Body>(value.clone()).map(|_| ())),
        "setSaml2SigningCertificate" => Some(serde_json::from_value::<set_saml2_signing_certificate::Body>(value.clone()).map(|_| ())),
        "uploadSaml2Metadata" => Some(serde_json::from_value::<upload_saml2_metadata::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getBackupCodesSettings", 200) => Some(serde_json::from_value::<get_backup_codes_settings::Answer200>(value.clone()).map(|_| ())),
        ("getGeolocation", 200) => Some(serde_json::from_value::<get_geolocation::Answer200>(value.clone()).map(|_| ())),
        ("getPolicies", 200) => Some(serde_json::from_value::<get_policies::Answer200>(value.clone()).map(|_| ())),
        ("clearPasskeyClient", 200) => Some(serde_json::from_value::<clear_passkey_client::Answer200>(value.clone()).map(|_| ())),
        ("clearPasskeyClients", 200) => Some(serde_json::from_value::<clear_passkey_clients::Answer200>(value.clone()).map(|_| ())),
        ("definePersonAttribute", 200) => Some(serde_json::from_value::<define_person_attribute::Answer200>(value.clone()).map(|_| ())),
        ("deleteNamedAuthnPolicy", 200) => Some(serde_json::from_value::<delete_named_authn_policy::Answer200>(value.clone()).map(|_| ())),
        ("removePersonAttribute", 200) => Some(serde_json::from_value::<remove_person_attribute::Answer200>(value.clone()).map(|_| ())),
        ("resetAttributesPolicy", 200) => Some(serde_json::from_value::<reset_attributes_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetAuthnPolicy", 200) => Some(serde_json::from_value::<reset_authn_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetLocalePolicy", 200) => Some(serde_json::from_value::<reset_locale_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetPasskeyPolicy", 200) => Some(serde_json::from_value::<reset_passkey_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetPasswordPolicy", 200) => Some(serde_json::from_value::<reset_password_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetPostLoginPolicy", 200) => Some(serde_json::from_value::<reset_post_login_policy::Answer200>(value.clone()).map(|_| ())),
        ("resetServiceAccountPolicy", 200) => Some(serde_json::from_value::<reset_service_account_policy::Answer200>(value.clone()).map(|_| ())),
        ("saveAttributesPolicy", 200) => Some(serde_json::from_value::<save_attributes_policy::Answer200>(value.clone()).map(|_| ())),
        ("saveAuthnPolicy", 200) => Some(serde_json::from_value::<save_authn_policy::Answer200>(value.clone()).map(|_| ())),
        ("saveLocalePolicy", 200) => Some(serde_json::from_value::<save_locale_policy::Answer200>(value.clone()).map(|_| ())),
        ("saveNamedAuthnPolicy", 200) => Some(serde_json::from_value::<save_named_authn_policy::Answer200>(value.clone()).map(|_| ())),
        ("savePasskeyPolicy", 200) => Some(serde_json::from_value::<save_passkey_policy::Answer200>(value.clone()).map(|_| ())),
        ("savePasswordPolicy", 200) => Some(serde_json::from_value::<save_password_policy::Answer200>(value.clone()).map(|_| ())),
        ("savePostLoginPolicy", 200) => Some(serde_json::from_value::<save_post_login_policy::Answer200>(value.clone()).map(|_| ())),
        ("saveServiceAccountPolicy", 200) => Some(serde_json::from_value::<save_service_account_policy::Answer200>(value.clone()).map(|_| ())),
        ("getPolicyTransfer", 200) => Some(serde_json::from_value::<get_policy_transfer::Answer200>(value.clone()).map(|_| ())),
        ("exportPolicies", 200) => Some(serde_json::from_value::<export_policies::Answer200>(value.clone()).map(|_| ())),
        ("importPolicies", 200) => Some(serde_json::from_value::<import_policies::Answer200>(value.clone()).map(|_| ())),
        ("inspectPolicyExport", 200) => Some(serde_json::from_value::<inspect_policy_export::Answer200>(value.clone()).map(|_| ())),
        ("updatePersonAttribute", 200) => Some(serde_json::from_value::<update_person_attribute::Answer200>(value.clone()).map(|_| ())),
        ("getRisc", 200) => Some(serde_json::from_value::<get_risc::Answer200>(value.clone()).map(|_| ())),
        ("getRiscAccounts", 200) => Some(serde_json::from_value::<get_risc_accounts::Answer200>(value.clone()).map(|_| ())),
        ("clearRiscAccounts", 200) => Some(serde_json::from_value::<clear_risc_accounts::Answer200>(value.clone()).map(|_| ())),
        ("emitRiscEvent", 200) => Some(serde_json::from_value::<emit_risc_event::Answer200>(value.clone()).map(|_| ())),
        ("resetRiscAccount", 200) => Some(serde_json::from_value::<reset_risc_account::Answer200>(value.clone()).map(|_| ())),
        ("getRisk", 200) => Some(serde_json::from_value::<get_risk::Answer200>(value.clone()).map(|_| ())),
        ("acceptRiskProviderTerms", 200) => Some(serde_json::from_value::<accept_risk_provider_terms::Answer200>(value.clone()).map(|_| ())),
        ("activateRiskDataset", 200) => Some(serde_json::from_value::<activate_risk_dataset::Answer200>(value.clone()).map(|_| ())),
        ("deleteRiskDatasetVersion", 200) => Some(serde_json::from_value::<delete_risk_dataset_version::Answer200>(value.clone()).map(|_| ())),
        ("importRiskDataset", 200) => Some(serde_json::from_value::<import_risk_dataset::Answer200>(value.clone()).map(|_| ())),
        ("getRiskMetrics", 200) => Some(serde_json::from_value::<get_risk_metrics::Answer200>(value.clone()).map(|_| ())),
        ("reloadRiskDatasetVersion", 200) => Some(serde_json::from_value::<reload_risk_dataset_version::Answer200>(value.clone()).map(|_| ())),
        ("rollbackRiskDataset", 200) => Some(serde_json::from_value::<rollback_risk_dataset::Answer200>(value.clone()).map(|_| ())),
        ("uploadRiskDataset", 200) => Some(serde_json::from_value::<upload_risk_dataset::Answer200>(value.clone()).map(|_| ())),
        ("uploadRiskDataset", 202) => Some(serde_json::from_value::<upload_risk_dataset::Answer202>(value.clone()).map(|_| ())),
        ("getRoles", 200) => Some(serde_json::from_value::<get_roles::Answer200>(value.clone()).map(|_| ())),
        ("addRoleConferringClient", 200) => Some(serde_json::from_value::<add_role_conferring_client::Answer200>(value.clone()).map(|_| ())),
        ("addRoleMember", 200) => Some(serde_json::from_value::<add_role_member::Answer200>(value.clone()).map(|_| ())),
        ("addRoleOwner", 200) => Some(serde_json::from_value::<add_role_owner::Answer200>(value.clone()).map(|_| ())),
        ("addRolePermission", 200) => Some(serde_json::from_value::<add_role_permission::Answer200>(value.clone()).map(|_| ())),
        ("createRole", 200) => Some(serde_json::from_value::<create_role::Answer200>(value.clone()).map(|_| ())),
        ("deleteRole", 200) => Some(serde_json::from_value::<delete_role::Answer200>(value.clone()).map(|_| ())),
        ("describeRole", 200) => Some(serde_json::from_value::<describe_role::Answer200>(value.clone()).map(|_| ())),
        ("previewRoleIssuance", 200) => Some(serde_json::from_value::<preview_role_issuance::Answer200>(value.clone()).map(|_| ())),
        ("removeRoleConferringClient", 200) => Some(serde_json::from_value::<remove_role_conferring_client::Answer200>(value.clone()).map(|_| ())),
        ("removeRoleMember", 200) => Some(serde_json::from_value::<remove_role_member::Answer200>(value.clone()).map(|_| ())),
        ("removeRoleOwner", 200) => Some(serde_json::from_value::<remove_role_owner::Answer200>(value.clone()).map(|_| ())),
        ("removeRolePermission", 200) => Some(serde_json::from_value::<remove_role_permission::Answer200>(value.clone()).map(|_| ())),
        ("getSamlAssertions", 200) => Some(serde_json::from_value::<get_saml_assertions::Answer200>(value.clone()).map(|_| ())),
        ("resetSamlAssertions", 200) => Some(serde_json::from_value::<reset_saml_assertions::Answer200>(value.clone()).map(|_| ())),
        ("setSamlAssertions", 200) => Some(serde_json::from_value::<set_saml_assertions::Answer200>(value.clone()).map(|_| ())),
        ("getSamlIdpInitiatedApplications", 200) => Some(serde_json::from_value::<get_saml_idp_initiated_applications::Answer200>(value.clone()).map(|_| ())),
        ("getSaml11RelyingParties", 200) => Some(serde_json::from_value::<get_saml11_relying_parties::Answer200>(value.clone()).map(|_| ())),
        ("registerSaml11RelyingParty", 200) => Some(serde_json::from_value::<register_saml11_relying_party::Answer200>(value.clone()).map(|_| ())),
        ("getSaml2ServiceProviders", 200) => Some(serde_json::from_value::<get_saml2_service_providers::Answer200>(value.clone()).map(|_| ())),
        ("confirmSaml2SigningCertificate", 200) => Some(serde_json::from_value::<confirm_saml2_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("discardSaml2SigningCertificate", 200) => Some(serde_json::from_value::<discard_saml2_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("importSaml2MetadataFromMdq", 200) => Some(serde_json::from_value::<import_saml2_metadata_from_mdq::Answer200>(value.clone()).map(|_| ())),
        ("refreshSaml2Metadata", 200) => Some(serde_json::from_value::<refresh_saml2_metadata::Answer200>(value.clone()).map(|_| ())),
        ("registerSaml2ServiceProvider", 200) => Some(serde_json::from_value::<register_saml2_service_provider::Answer200>(value.clone()).map(|_| ())),
        ("removeSaml2LogoutService", 200) => Some(serde_json::from_value::<remove_saml2_logout_service::Answer200>(value.clone()).map(|_| ())),
        ("removeSaml2SigningCertificate", 200) => Some(serde_json::from_value::<remove_saml2_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("addSaml2LogoutService", 200) => Some(serde_json::from_value::<add_saml2_logout_service::Answer200>(value.clone()).map(|_| ())),
        ("setSaml2MetadataSigningCertificate", 200) => Some(serde_json::from_value::<set_saml2_metadata_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("setSaml2SigningCertificate", 200) => Some(serde_json::from_value::<set_saml2_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("uploadSaml2Metadata", 200) => Some(serde_json::from_value::<upload_saml2_metadata::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
