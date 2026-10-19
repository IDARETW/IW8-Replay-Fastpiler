"""Conservative static reader-code closure for display metadata cache identity.

Only the indexed read entry points are roots. Their reachable Python definitions,
referenced module globals, class shells/methods, and imported local modules are
included automatically. An unresolved dynamic import falls back to the complete
module digest so an opaque dependency can never be silently ignored.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _module_path(name: str, root: Path):
    if not name or name.startswith("."):
        return None
    parts = name.split(".")
    candidate = root.joinpath(*parts).with_suffix(".py")
    if candidate.is_file():
        return candidate.resolve()
    package = root.joinpath(*parts, "__init__.py")
    return package.resolve() if package.is_file() else None


def _is_main_guard(node):
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__" and
            any(isinstance(value, ast.Constant) and value.value == "__main__"
                for value in node.test.comparators))


def reader_code_identity(path: str | Path, entrypoints, local_root: str | Path) -> dict:
    """Return a stable digest for entrypoints and their statically reachable code."""
    source = Path(path).resolve(strict=True)
    root = Path(local_root).resolve(strict=True)
    if not source.is_relative_to(root):
        raise ValueError("reader module must be inside its local source root")
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    module_name = source.relative_to(root).with_suffix("").as_posix().replace("/", ".")
    functions = {}
    classes = {}
    globals_by_name = {}
    module_imports = {}
    initialization = [node for node in tree.body
                      if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                      and not _is_main_guard(node)]
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        globals_by_name[child.id] = node
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_imports[alias.asname or alias.name.split(".")[0]] = (alias.name, None)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            for alias in node.names:
                module_imports[alias.asname or alias.name] = (base, alias.name)

    class_methods = {name: {node.name: node for node in cls.body
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                     for name, cls in classes.items()}
    pending = []
    for entry in entrypoints:
        if entry in functions:
            pending.append(("function", entry))
            continue
        if "." in entry:
            owner, member = entry.split(".", 1)
            if owner not in classes or member not in class_methods[owner]:
                raise ValueError(f"reader entrypoint is unresolved: {entry}")
            pending.append(("method", owner, member))
            pending.append(("class", owner))
            continue
        if entry in classes:
            pending.append(("class", entry))
            continue
        raise ValueError(f"reader entrypoint is unresolved: {entry}")

    reached = {}
    dependency_hashes = {}
    dynamic_fallback = False
    local_inventory_fallback = False
    scanned_dependencies = set()

    def include_import(module: str, imported_name=None, current_module=None):
        nonlocal dynamic_fallback, local_inventory_fallback
        current_module = current_module or module_name
        if module.startswith("."):
            level = len(module) - len(module.lstrip("."))
            suffix = module[level:]
            package = current_module.split(".")[:-1]
            if level - 1 > len(package):
                local_inventory_fallback = True
                return
            package = package[:len(package) - (level - 1)] if level > 1 else package
            module = ".".join([*package, *([suffix] if suffix else [])])
            if not module and imported_name:
                module, imported_name = imported_name, None
            if not module:
                local_inventory_fallback = True
                return
        if module in (module_name, module_name.rsplit(".", 1)[0]):
            return
        candidates = [module]
        if imported_name and imported_name != "*":
            candidates.append(module + "." + imported_name)
        found = False
        for candidate_name in candidates:
            dep = _module_path(candidate_name, root)
            if dep is None:
                continue
            found = True
            if candidate_name in scanned_dependencies:
                continue
            scanned_dependencies.add(candidate_name)
            dependency_hashes[candidate_name] = _hash(dep.read_bytes())
            try:
                dep_tree = ast.parse(dep.read_text(encoding="utf-8"), filename=str(dep))
            except (OSError, SyntaxError, UnicodeError):
                local_inventory_fallback = True
                continue
            for child in ast.walk(dep_tree):
                if isinstance(child, ast.Import):
                    for alias in child.names:
                        include_import(alias.name, current_module=candidate_name)
                elif isinstance(child, ast.ImportFrom):
                    relative = ("." * child.level) + (child.module or "")
                    for alias in child.names:
                        include_import(relative, alias.name, current_module=candidate_name)
                elif isinstance(child, ast.Call):
                    func = child.func
                    dynamic = (isinstance(func, ast.Name) and func.id == "__import__") or (
                        isinstance(func, ast.Attribute) and func.attr == "import_module")
                    if dynamic:
                        if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                            include_import(child.args[0].value)
                        else:
                            local_inventory_fallback = True
        # An unresolved relative or dynamic local import is handled by hashing
        # the complete local source inventory below, never silently ignored.
        if not found and (module.startswith(".") or module.startswith("workstation_")):
            local_inventory_fallback = True

    for init_node in initialization:
        for child in ast.walk(init_node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    include_import(alias.name)
            elif isinstance(child, ast.ImportFrom):
                relative = ("." * child.level) + (child.module or "")
                for alias in child.names:
                    include_import(relative, alias.name)
            elif isinstance(child, ast.Call):
                func = child.func
                if ((isinstance(func, ast.Name) and func.id == "__import__") or
                        (isinstance(func, ast.Attribute) and func.attr == "import_module")):
                    if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                        include_import(child.args[0].value)
                    else:
                        local_inventory_fallback = True

    while pending:
        kind, *parts = pending.pop()
        key = ".".join([kind, *parts])
        if key in reached:
            continue
        if kind == "function":
            node = functions[parts[0]]
            owner = None
        elif kind == "method":
            owner, member = parts
            node = class_methods[owner][member]
        elif kind == "class":
            owner = parts[0]
            cls = classes[owner]
            shell = [item for item in cls.body
                     if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
            node = ast.ClassDef(name=cls.name, bases=cls.bases, keywords=cls.keywords,
                                body=shell or [ast.Pass()], decorator_list=cls.decorator_list)
            owner = None
        elif kind == "global":
            node = globals_by_name[parts[0]]
            owner = None
        else:
            raise AssertionError(kind)
        reached[key] = ast.dump(node, annotate_fields=True, include_attributes=False)

        names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
        attrs = [item for item in ast.walk(node) if isinstance(item, ast.Attribute)]
        local_instance_types = {}
        for item in ast.walk(node):
            if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call) and isinstance(item.value.func, ast.Name):
                type_name = item.value.func.id
                if type_name in functions:
                    returned = functions[type_name].returns
                    type_name = returned.id if isinstance(returned, ast.Name) else ""
                if type_name in classes:
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            local_instance_types[target.id] = type_name
            elif isinstance(item, ast.Assign) and isinstance(item.value, ast.Call) and isinstance(item.value.func, ast.Attribute):
                receiver = item.value.func.value
                type_name = receiver.id if isinstance(receiver, ast.Name) and receiver.id in classes else ""
                if type_name in classes:
                    returned = class_methods[type_name].get(item.value.func.attr)
                    annotation = getattr(returned, "returns", None)
                    type_name = annotation.id if isinstance(annotation, ast.Name) and annotation.id in classes else type_name
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            local_instance_types[target.id] = type_name
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                annotation = item.annotation
                if isinstance(annotation, ast.Name) and annotation.id in classes:
                    local_instance_types[item.target.id] = annotation.id
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.returns:
                if isinstance(item.returns, ast.Name) and item.returns.id in classes:
                    local_instance_types[item.name] = item.returns.id
        if any(isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and
               item.func.id in ("getattr", "exec", "eval") for item in ast.walk(node)):
            # These constructs can resolve code dependencies from runtime data.
            dynamic_fallback = True
        for name in names:
            if name in functions:
                pending.append(("function", name))
            if name in classes:
                pending.append(("class", name))
                if "__init__" in class_methods[name]:
                    pending.append(("method", name, "__init__"))
            if name in globals_by_name:
                pending.append(("global", name))
            if name in module_imports:
                imported_module, imported_name = module_imports[name]
                if imported_module.startswith("."):
                    local_inventory_fallback = True
                else:
                    include_import(imported_module, imported_name)

        for attr in attrs:
            if owner and isinstance(attr.value, ast.Name) and attr.value.id in ("self", "cls"):
                if attr.attr in class_methods.get(owner, {}):
                    pending.append(("method", owner, attr.attr))
            if isinstance(attr.value, ast.Name) and attr.value.id in classes:
                class_name = attr.value.id
                if attr.attr in class_methods.get(class_name, {}):
                    pending.append(("method", class_name, attr.attr))
            if isinstance(attr.value, ast.Name) and attr.value.id in local_instance_types:
                class_name = local_instance_types[attr.value.id]
                if attr.attr in class_methods.get(class_name, {}):
                    pending.append(("method", class_name, attr.attr))
                elif "__getattr__" in class_methods.get(class_name, {}):
                    pending.append(("method", class_name, "__getattr__"))
                else:
                    known_fields = set(class_methods.get(class_name, {}))
                    cls_node = classes[class_name]
                    for class_item in ast.walk(cls_node):
                        if isinstance(class_item, (ast.Assign, ast.AnnAssign)):
                            targets = class_item.targets if isinstance(class_item, ast.Assign) else [class_item.target]
                            known_fields.update(target.id for target in targets if isinstance(target, ast.Name))
                        if isinstance(class_item, ast.Attribute) and isinstance(class_item.value, ast.Name) and class_item.value.id == "self":
                            known_fields.add(class_item.attr)
                    if attr.attr not in known_fields:
                        if "__getattribute__" in class_methods.get(class_name, {}):
                            pending.append(("method", class_name, "__getattribute__"))
                        else:
                            # The local receiver type is known, but its attribute
                            # implementation is not; use the conservative module fallback.
                            dynamic_fallback = True
            if isinstance(attr.value, ast.Name) and attr.value.id in module_imports:
                imported_module, _ = module_imports[attr.value.id]
                if not imported_module.startswith("."):
                    include_import(imported_module)
                else:
                    local_inventory_fallback = True

        for child in ast.walk(node):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                if isinstance(child, ast.Import):
                    for alias in child.names:
                        include_import(alias.name)
                else:
                    imported = ("." * child.level) + (child.module or "")
                    for alias in child.names:
                        include_import(imported, alias.name)
            if isinstance(child, ast.Call):
                func = child.func
                dynamic = (isinstance(func, ast.Name) and func.id == "__import__") or (
                    isinstance(func, ast.Attribute) and func.attr == "import_module")
                if dynamic:
                    if child.args and isinstance(child.args[0], ast.Constant) and \
                            isinstance(child.args[0].value, str):
                        include_import(child.args[0].value)
                    else:
                        local_inventory_fallback = True

        # For reached dataclasses, serialize every method and property so
        # generated initialization and post-init behavior are identity-bound.
        if kind in ("class", "method"):
            class_name = parts[0]
            cls = classes[class_name]
            dataclass_like = any((isinstance(decorator, ast.Name) and decorator.id == "dataclass") or
                                 (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
                                  and decorator.func.id == "dataclass") for decorator in cls.decorator_list)
            if dataclass_like and kind == "class":
                for method_name in class_methods[class_name]:
                    pending.append(("method", class_name, method_name))

    if local_inventory_fallback:
        inventory = {}
        for dep in sorted(root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()):
            inventory[dep.relative_to(root).as_posix()] = _hash(dep.read_bytes())
        dependency_hashes["<local-source-inventory>"] = _hash(json_bytes(inventory))

    if dynamic_fallback:
        reader_digest = _hash(source.read_bytes() + json_bytes(sorted(dependency_hashes.items())))
        strategy = "full-module-dynamic-import-fallback"
    else:
        payload = json_bytes(dict(module=module_name,
                                  initialization=[ast.dump(node, annotate_fields=True,
                                                           include_attributes=False) for node in initialization],
                                  reached=sorted(reached.items()),
                                  local_dependencies=sorted(dependency_hashes.items())))
        reader_digest = _hash(payload)
        strategy = "ast-reader-closure-v2"
    return dict(sha256=reader_digest, strategy=strategy,
                entrypoints=sorted(entrypoints),
                reachable_definitions=len(reached),
                local_dependencies=dependency_hashes)


def json_bytes(value) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
