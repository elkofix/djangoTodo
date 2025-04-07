from django.urls import path
from . import views

urlpatterns = [
    path('home', views.home, name='home'),
    path('create-task/', views.create_task, name='create-task'),
    path('edit-task/<int:task_id>/', views.edit_task, name='edit-task'),
    path('delete-task/<int:task_id>/', views.delete_task, name='delete-task'),
    path('list-tasks/', views.list_tasks, name='list-tasks'),
    path('send-email/', views.send_email_view, name='send-email'),
    path("register/", views.register, name="register"),
    path("", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path("admins/roles/", views.manage_roles, name="manage-roles"),
    path("assign-permissions/", views.assign_permissions, name="assign-permissions"),

]