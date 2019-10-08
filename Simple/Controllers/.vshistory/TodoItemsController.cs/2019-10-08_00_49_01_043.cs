using System;
using System.Collections.Generic;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using Simple.Data;
using Simple.Models;

namespace Simple.Controllers
{
    [Route("api/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [ApiController]
    [Controller]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context) =>
            Context = context ?? throw new ArgumentNullException(nameof(context));

        public ApplicationDbContext Context { get; }

        [HttpGet]
        public async IAsyncEnumerable<TodoItem> Get()
        {
            IAsyncEnumerable<TodoItem> todoItems = Context.TodoItems.AsNoTracking().AsAsyncEnumerable();
            await foreach (TodoItem item in todoItems) yield return item;
        }

        //متدهای HTTP          CRUD مثال
        //==============       =============       =================================
        //POST                 Create              Link to /customers/{id} شامل ID جدید
        //GET                  Read                نمایش لیستی از مشتریان، صفحه بندی
        //PUT                  Update/Replace      جایگزین کردن هر اسمی درون لیست مشتریان
        //PATCH                Update/Modify       ویرایش کردن یک نام از لیست تمام مشتریان
        //DELETE               Delete              حذف کردن نام یک مشتری و یا مشتریان

        //Examine the GET methods
        //These methods implement two GET endpoints:
        //GET /api/TodoItems
        //GET /api/TodoItems/{id}
        //Test the app by calling the two endpoints from a browser or Postman.For example:
        //https://localhost:5001/api/TodoItems
        //https://localhost:5001/api/TodoItems/1
        //[
        //  {
        //    "id": 1,
        //    "name": "Item1",
        //    "isComplete": false
        //  }
        //]

        //[HttpGet("[controller]/[action]/{id}", Name = "TodoItem")]
        [HttpGet("{id:long}")] // GET: api/TodoItems/5
        public ActionResult<TodoItem> GetTodoItem(long id) => new TodoItem { Id = id };

        // POST: api/TodoItems
        //[HttpPost("/AddTodoItem")]
        [HttpPost]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken ct = default)
        {
            await Context.TodoItems.AddAsync(todoItem, ct);
            await Context.SaveChangesAsync(ct);

            //The CreatedAtAction method:
            //Returns an HTTP 201 status code if successful.
            return CreatedAtAction(/*"GetTodoItem"*/nameof(GetTodoItem), new { id = todoItem.Id }, todoItem);
        }

        // PUT: api/TodoItems/5
        [HttpPut("{id:long}")]
        public async Task<IActionResult> PutTodoItem(long id, TodoItem todoItem, CancellationToken ct = default)
        {
            if (id != todoItem.Id) return BadRequest();

            Context.Entry(todoItem).State = EntityState.Modified;
            //Context.TodoItems.Update(todoItem);

            try
            {
                await Context.SaveChangesAsync(ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                var item = await Context.TodoItems.FindAsync(id);
                if (item != null) return NotFound();
                else throw;
            }

            return NoContent();
        }

        // DELETE: api/TodoItems/5
        [HttpDelete("{id:long}")]
        public async Task<ActionResult<TodoItem>> DeleteTodoItem(long id, CancellationToken ct = default)
        {
            var todoItem = await Context.TodoItems.FindAsync(id);
            if (todoItem == null) return NotFound();

            Context.TodoItems.Remove(todoItem);
            await Context.SaveChangesAsync(ct);

            return todoItem;
        }

    }
}
