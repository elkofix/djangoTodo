import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from task.models import Status, Task
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import permission_required
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User, Permission
from django.shortcuts import render, redirect
from .models import Task
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import Task
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from .models import Task


def is_role_admin(user):
    return user.groups.filter(name="admin").exists() or user.is_superuser

@login_required
def assign_permissions(request):
    tasks = Task.objects.all()
    users = User.objects.all()

    if request.method == "POST":
        user_id = request.POST.get("user_id")
        task_id = request.POST.get("task_id")
        permission_type = request.POST.get("permission_type")

        user = User.objects.get(id=user_id)
        permission = Permission.objects.get(codename=f"{permission_type}_task_{task_id}")
        print("se le agrego al usuario el permiso")
        print(f"{permission_type}_task_{task_id}")
        user.user_permissions.add(permission)

    return render(request, "assign_permissions.html", {"tasks": tasks, "users": users})


@login_required
@user_passes_test(is_role_admin)  # Solo admins pueden acceder
def manage_roles(request):
    users = User.objects.all()
    groups = Group.objects.all()

    if request.method == "POST":
        user_id = request.POST.get("user_id")
        group_id = request.POST.get("group_id")
        action = request.POST.get("action")

        user = User.objects.get(id=user_id)
        group = Group.objects.get(id=group_id)

        if action == "add":
            user.groups.add(group)
            messages.success(request, f"Se añadió {user.username} al grupo {group.name}.")
        elif action == "remove":
            user.groups.remove(group)
            messages.warning(request, f"Se eliminó {user.username} del grupo {group.name}.")

        return redirect("manage-roles")

    return render(request, "roles/manage_roles.html", {"users": users, "groups": groups})

def home(request):
    return render(request, 'home.html')




@login_required
def list_tasks(request):
    tasks = Task.objects.all()
    print(request.user.get_all_permissions())

    filtered_tasks = []
    for task in tasks:
        perm_view = f"task.view_task_{task.id}"
        perm_edit = f"task.edit_task_{task.id}"
        perm_delete = f"task.delete_task_{task.id}"
        print(perm_view)
    
        if request.user.has_perm(perm_view):
            print("tiene edit")
            print(request.user.has_perm(perm_edit))
            # Agregar permisos específicos a la tarea
            task.can_edit = request.user.has_perm(perm_edit)
            task.can_delete = request.user.has_perm(perm_delete)
            filtered_tasks.append(task)

    return render(request, "list_tasks.html", {"tasks": filtered_tasks})


@permission_required("task.add_task", raise_exception=True)
@login_required
def create_task(request):
    if request.method == 'POST':
        name: str = request.POST.get('task-name', '')
        description: str = request.POST.get('task-description', '').strip()
        status_id: Status = Status.objects.get(name='Pendiente')

        deadline_str: str = request.POST.get('task-deadline', '').strip()
        deadline: datetime.datetime = None

        if deadline_str:
            try:
                deadline = datetime.datetime.strptime(deadline_str, '%Y-%m-%d')

            except ValueError:
                pass

        Task.objects.create(
            name=name,
            description=description,
            deadline=deadline,
            status_id=status_id,
        )

        messages.success(request, '¡Tarea creada exitosamente!')

        return redirect('list-tasks')

    return render(request, 'create_task.html')

@login_required
def edit_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if not request.user.has_perm(f"task.edit_task_{task.id}"):
        raise PermissionDenied("No tienes permiso para editar esta tarea.")
    if request.method == 'POST':
        task: Task = Task.objects.get(id=task_id)

        task.name = request.POST.get('task-name', '')
        task.description = request.POST.get('task-description', '').strip()

        deadline_str: str = request.POST.get('task-deadline', '').strip()
        deadline: datetime.datetime = None

        if deadline_str:
            try:
                deadline = datetime.datetime.strptime(deadline_str, '%Y-%m-%d')

            except ValueError:
                pass

        task.deadline = deadline
        task.save()

        messages.success(request, '¡Tarea actualizada exitosamente!')

        return redirect('list-tasks')

    return render(request, 'edit_task.html', {
        'task': Task.objects.get(id=task_id),
        'task_statuses': Status.objects.all(),
    })

@login_required
def delete_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if not request.user.has_perm(f"task.delete_task_{task.id}"):
        raise PermissionDenied("No tienes permiso para eliminar esta tarea.")
    Task.objects.get(id=task_id).delete()

    messages.success(request, '¡Tarea eliminada exitosamente!')

    return redirect('list-tasks')

def send_email_view(request):
    if request.method == 'POST':
        subject = request.POST.get('subject', '')
        message = request.POST.get('message', '')
        recipient = request.POST.get('recipient', '')

        if subject and message and recipient:
            try:
                send_mail(subject, message, 'tu_correo@gmail.com', [recipient])
                messages.success(request, '¡Correo enviado exitosamente!')
            except Exception as e:
                messages.error(request, f'Error al enviar el correo: {e}')
        else:
            messages.error(request, 'Todos los campos son obligatorios.')

        return redirect('send-email')

    return render(request, 'send_email.html')



def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]

        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "El usuario ya existe")
        else:
            user = User.objects.create_user(username=username, email=email, password=password1)

            # Asignar grupo "Usuarios" automáticamente
            user_group, created = Group.objects.get_or_create(name="Usuarios")
            user.groups.add(user_group)

            login(request, user)
            messages.success(request, "¡Registro exitoso!")
            return redirect("list-tasks")

    return render(request, "auth/register.html")

def user_login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect("list-tasks")
        else:
            messages.error(request, "Usuario o contraseña incorrectos")

    return render(request, "auth/login.html")

def user_logout(request):
    logout(request)
    messages.success(request, "Sesión cerrada correctamente")
    return redirect("login")
