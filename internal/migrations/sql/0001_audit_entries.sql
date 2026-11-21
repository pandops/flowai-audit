-- audit entries: immutable, ordered by the global audit_id commit sequence.
CREATE SEQUENCE {{schema}}.audit_id_seq AS bigint MINVALUE 1 START 1;

CREATE TABLE {{schema}}.audit_entries (
    audit_id       bigint PRIMARY KEY CHECK (audit_id > 0),
    team_id        bigint CHECK (team_id > 0),
    publisher      text NOT NULL CHECK (publisher <> ''),
    publisher_seq  bigint NOT NULL CHECK (publisher_seq > 0),
    source_service text NOT NULL CHECK (source_service <> ''),
    actor_type     text NOT NULL CHECK (actor_type IN ('operator', 'administrator')),
    actor_id       bigint CHECK (actor_id > 0),
    actor_subject  text,
    action         text NOT NULL CHECK (action <> ''),
    resource_type  text NOT NULL CHECK (resource_type <> ''),
    resource_id    bigint CHECK (resource_id > 0),
    request_id     bigint NOT NULL CHECK (request_id > 0),
    outcome        text NOT NULL CHECK (outcome <> ''),
    occurred_at    timestamptz NOT NULL,
    changes        jsonb CHECK (changes IS NULL OR jsonb_typeof(changes) = 'object'),
    stored_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (publisher, publisher_seq),
    CHECK ((actor_type = 'operator' AND team_id IS NOT NULL AND actor_id IS NOT NULL AND actor_subject IS NULL)
        OR (actor_type = 'administrator' AND team_id IS NULL AND actor_id IS NULL AND actor_subject IS NOT NULL AND actor_subject <> ''))
);

CREATE INDEX audit_entries_team_order ON {{schema}}.audit_entries (team_id, occurred_at DESC, audit_id DESC)
    WHERE team_id IS NOT NULL;

-- Messages acknowledged without an entry (payload named another team).
CREATE TABLE {{schema}}.rejected_messages (
    publisher     text NOT NULL CHECK (publisher <> ''),
    publisher_seq bigint NOT NULL CHECK (publisher_seq > 0),
    subject       text NOT NULL,
    reason        text NOT NULL,
    rejected_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (publisher, publisher_seq)
);

CREATE FUNCTION {{schema}}.audit_entries_immutable() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit entries are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_entries_immutable
    BEFORE UPDATE OR DELETE ON {{schema}}.audit_entries
    FOR EACH ROW EXECUTE FUNCTION {{schema}}.audit_entries_immutable();

CREATE TRIGGER audit_entries_no_truncate
    BEFORE TRUNCATE ON {{schema}}.audit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION {{schema}}.audit_entries_immutable();
