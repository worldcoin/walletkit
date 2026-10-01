"""The review stages behind the auto-review composite action.

Each stage is a module with a ``run(config)`` function, dispatched by ``auto_review.<stage>``.
The stages only talk to each other through the files in ``state``.
"""
