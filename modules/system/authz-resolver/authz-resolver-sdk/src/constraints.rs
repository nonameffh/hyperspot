//! Constraint types for authorization decisions.
//!
//! Constraints represent row-level filtering conditions returned by the PDP.
//! They are compiled into `AccessScope` by the PEP compiler.
//!
//! ## Supported predicates
//!
//! Only `Eq` and `In` predicates are supported in the first iteration.
//!
//! ## Future extensions
//!
//! Additional predicate types (`in_tenant_subtree`, `in_group`,
//! `in_group_subtree`) are planned. See the authorization design document
//! (`docs/arch/authorization/DESIGN.md`) for the full predicate taxonomy.

use crate::pep::IntoPropertyValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A constraint on a specific resource property.
///
/// Multiple constraints within a response are `ORed`:
/// a resource matches if it satisfies ANY constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// The predicates within this constraint. All predicates are `ANDed`:
    /// a resource matches this constraint only if ALL predicates are satisfied.
    pub predicates: Vec<Predicate>,
}

/// A predicate comparing a resource property to a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Predicate {
    /// Equality: `resource_property = value`
    Eq(EqPredicate),
    /// Set membership: `resource_property IN (values)`
    In(InPredicate),
}

/// Equality predicate: `property = value`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqPredicate {
    /// Resource property name (e.g., `pep_properties::OWNER_TENANT_ID`, `pep_properties::RESOURCE_ID`).
    pub property: String,
    /// The value to match (UUID string, plain string, number, bool, etc.).
    pub value: Value,
}

impl EqPredicate {
    /// Create an equality predicate with any convertible value.
    #[must_use]
    pub fn new(property: impl Into<String>, value: impl IntoPropertyValue) -> Self {
        Self {
            property: property.into(),
            value: value.into_filter_value(),
        }
    }
}

/// Set membership predicate: `property IN (values)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InPredicate {
    /// Resource property name (e.g., `pep_properties::OWNER_TENANT_ID`, `pep_properties::RESOURCE_ID`).
    pub property: String,
    /// The set of values to match against.
    pub values: Vec<Value>,
}

impl InPredicate {
    /// Create an `IN` predicate from an iterator of convertible values.
    #[must_use]
    pub fn new<V: IntoPropertyValue>(
        property: impl Into<String>,
        values: impl IntoIterator<Item = V>,
    ) -> Self {
        Self {
            property: property.into(),
            values: values
                .into_iter()
                .map(IntoPropertyValue::into_filter_value)
                .collect(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use modkit_security::pep_properties;
    use serde_json::json;

    #[test]
    fn constraint_serialization_roundtrip() {
        let constraint = Constraint {
            predicates: vec![
                Predicate::In(InPredicate {
                    property: pep_properties::OWNER_TENANT_ID.to_owned(),
                    values: vec![
                        json!("11111111-1111-1111-1111-111111111111"),
                        json!("22222222-2222-2222-2222-222222222222"),
                    ],
                }),
                Predicate::Eq(EqPredicate {
                    property: pep_properties::RESOURCE_ID.to_owned(),
                    value: json!("33333333-3333-3333-3333-333333333333"),
                }),
            ],
        };

        let json_str = serde_json::to_string(&constraint).unwrap();
        let deserialized: Constraint = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.predicates.len(), 2);
    }

    #[test]
    fn predicate_tag_serialization() {
        let eq = Predicate::Eq(EqPredicate {
            property: pep_properties::RESOURCE_ID.to_owned(),
            value: json!("00000000-0000-0000-0000-000000000000"),
        });

        let json_str = serde_json::to_string(&eq).unwrap();
        assert!(json_str.contains(r#""op":"eq""#));

        let in_pred = Predicate::In(InPredicate {
            property: pep_properties::OWNER_TENANT_ID.to_owned(),
            values: vec![json!("00000000-0000-0000-0000-000000000000")],
        });

        let json_str = serde_json::to_string(&in_pred).unwrap();
        assert!(json_str.contains(r#""op":"in""#));
    }
}
