/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic LIT reference project.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of the WinMagic Inc.
* Commercial License, which can be found at https://winmagic.com/en/legal/commercial_license/
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using LIT.ServerMVC.Data;
using LIT.ServerMVC.Data.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace LIT.ServerMVC.Controllers
{
    [Authorize]
    public class TodoItemController : Controller
    {
        private readonly ApplicationDbContext _context;

        public TodoItemController(ApplicationDbContext context)
        {
            _context = context;
        }

        private string? GetUserId() => User.FindFirstValue(ClaimTypes.NameIdentifier);

        // GET: TodoItem
        public async Task<IActionResult> Index()
        {
            var todoItems = _context.TodoItems.Where(t => t.UserId == Guid.Parse(GetUserId())).Include(t => t.User);
            return View(await todoItems.ToListAsync());
        }

        // GET: TodoItem/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var todoItem = await _context.TodoItems
                .Include(t => t.User)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (todoItem == null)
            {
                return NotFound();
            }

            if (!IsCurrentUserTodoItem(todoItem.UserId.ToString()))
            {
                return NotFound();
            }

            return View(todoItem);
        }

        // GET: TodoItem/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: TodoItem/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(TodoItemViewModel todoItem)
        {
            if (ModelState.IsValid)
            {

                var todoItems = await _context.TodoItems.Where(t => t.UserId == Guid.Parse(GetUserId())).Include(t => t.User).ToListAsync();
                if(todoItems.Count >= 5)
                {
                    ModelState.AddModelError("", "The maximum limit of 5 TODO items has been reached.");
                    return View();
                }

                var todo = new TodoItem
                {
                    Title = todoItem.Title,
                    Description = todoItem.Description,
                    UserId = Guid.Parse(GetUserId())
                };
                _context.Add(todo);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(todoItem);
        }

        // GET: TodoItem/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var todoItem = await _context.TodoItems.FindAsync(id);
            if (todoItem == null)
            {
                return NotFound();
            }

            if (!IsCurrentUserTodoItem(todoItem.UserId.ToString()))
            {
                return NotFound();
            }

            var todoViewModel = new TodoItemViewModel
            {
                Title = todoItem.Title,
                Description = todoItem.Description,
                IsCompleted = todoItem.IsCompleted
            };
            return View(todoViewModel);
        }

        // POST: TodoItem/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, TodoItemViewModel todoItem)
        {
            var todo = await _context.TodoItems.FindAsync(id);
            if (todo == null)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                if (!IsCurrentUserTodoItem(todo.UserId.ToString()))
                {
                    return NotFound();
                }
                try
                {
                    todo.Title = todoItem.Title;
                    todo.Description = todoItem.Description;
                    todo.IsCompleted = todoItem.IsCompleted;
                    _context.Update(todo);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    throw;
                }
                return RedirectToAction(nameof(Index));
            }
            return View(todoItem);
        }

        // GET: TodoItem/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var todoItem = await _context.TodoItems
                .Include(t => t.User)
                .FirstOrDefaultAsync(m => m.Id == id);

            if (todoItem == null)
            {
                return NotFound();
            }

            if (!IsCurrentUserTodoItem(todoItem.UserId.ToString()))
            {
                return NotFound();
            }

            return View(todoItem);
        }

        // POST: TodoItem/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var todoItem = await _context.TodoItems.FindAsync(id);

            if (todoItem != null)
            {

                if (IsCurrentUserTodoItem(todoItem.UserId.ToString()))
                {
                    _context.TodoItems.Remove(todoItem);
                }
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool IsCurrentUserTodoItem(string userId)
        {
            return userId == GetUserId();
        }
    }
}
