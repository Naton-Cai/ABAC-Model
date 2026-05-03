package app.abac

default allow := false

#we want to limit each role to specific columns in each table depending on it's role
#billing staff shouldn't need information on patient info and 
#should be limited to infomration relating to generting billing such as insurance info.
allow if {
    input.subject.role == "billing"
    input.context.action == "read"
    #the dictionary of the fields billing is allowed to access in each table
    billing_allowed_fields := {
        "patients": set(),
        "admissions": {"subject_id", "hadm_id", "insurance", "admission_type", "admit_provider_id"},
        "labevents": {"subject_id", "labevent_id", "itemid", "hadm_id"}
    }
    #we create a subset based on what each table is attempting to access. T
    #Then check if each column the user is trying to access is in the allowed subset, otherwise block.
    allowed := billing_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
}

#insurance case based on memebers of the insurance agency that needs 
allow if {
    input.subject.role == "insurance"
    input.context.action == "read"
    insurance_allowed_fields := {
        "patients": {"subject_id", "gender", "anchor_age"},
        "admissions": {"subject_id", "admission_type", "insurance", "marital_status"},
        "labevents": {"subject_id", "labevent_id", "itemid", "hadm_id", "value"},
    }
    allowed := insurance_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
    
    # Insurance provider must match the subject's admission insurance
    some admission in data.admissions
    admission.subject_id == input.resource.subject_id
    input.subject.provider == admission.insurance
}

//case_managers should only access subjects that match the cases they are managing
allow if {
    input.subject.role == "case_manager"
    input.context.action == "read"
    input.resource.subject_id in input.subject.patients
    case_manager_allowed_fields := {
        "patients": {"subject_id", "gender", "anchor_age", "anchor_year"},
        "admissions": {"subject_id", "hadm_id", "admittime", "dischtime", "admission_type", "admit_provider_id", "admission_location", "discharge_location"},
        "labevents": {"subject_id", "labevent_id", "itemid", "hadm_id", "order_provider_id", "value"}
    }
    allowed := case_manager_allowed_fields[input.resource.table]
    every field in input.resource.fields {
        field in allowed
    }
}