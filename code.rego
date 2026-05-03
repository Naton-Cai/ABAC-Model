package app.abac

default allow := false

allow if {
    input.subject.role == "billing"
    input.context.action == "read"
    billing_allowed_fields := {
        "patients": set(),
        "admissions": {"subject_id", "hadm_id", "insurance", "admission_type", "admit_provider_id"},
        "labevents": {"subject_id", "labevent_id", "itemid", "hadm_id"}
    }
    allowed := billing_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
}

allow if {
    input.subject.role == "insurance"
    input.context.action == "read"
    insurance_allowed_fields := {
        "patients": {"subject_id", "gender", "anchor_age"},
        "admissions": {"subject_id", "admission_type", "insurance", "marital_status"},
        "labevents": {"subject_id", "itemid", "hadm_id", "value"},
    }
    allowed := insurance_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
}

allow if {
    input.subject.role == "case_manager"
    input.context.action == "read"
    input.resource.subject_id in input.subject.patients
    case_manager_allowed_fields := {
        "patients": {"subject_id", "gender", "anchor_age", "anchor_year"},
        "admissions": {"subject_id", "hadm_id", "admittime", "dischtime", "admission_type", "admit_provider_id", "admission_location", "discharge_location"},
        "labevents": {"subject_id", "itemid", "hadm_id", "order_provider_id", "value"}
    }
    allowed := case_manager_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
}