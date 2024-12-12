/**
 * Automatic handling for maintaining created_at and updated_at timestamps
 * on tables
 */
CREATE OR REPLACE FUNCTION updateTimestamps() RETURNS TRIGGER AS $$ BEGIN IF TG_OP = 'INSERT' THEN NEW.created_at = NOW();

NEW.updated_at = NOW();

ELSE NEW.updated_at = NOW();

NEW.created_at = OLD.created_at;

END IF;

RETURN NEW;

END $$ LANGUAGE plpgsql;

/**
 * Automatic handling for maintaining created_by and updated_by timestamps
 * on tables
 */
CREATE OR REPLACE FUNCTION trackUser() RETURNS TRIGGER AS $$ BEGIN IF TG_OP = 'INSERT' THEN NEW.created_by = auth.uid();

NEW.updated_by = auth.uid();

ELSE NEW.updated_by = auth.uid();

NEW.created_by = OLD.created_by;

END IF;

RETURN NEW;

END $$ LANGUAGE plpgsql;
