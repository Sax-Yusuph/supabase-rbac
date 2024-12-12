-- Insert values into app_role table
INSERT INTO public.app_role (name) VALUES
    ('admin'),
    ('member');


    -- Insert values into app_permission table
    INSERT INTO public.app_permission (name) VALUES
        ('workspace.read'),
        ('workspace.delete');
